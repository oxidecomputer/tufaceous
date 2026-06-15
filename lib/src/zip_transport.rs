// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// ZIP is a somewhat dreadful archive format. We use it as the repository
// format of choice for Tufaceous because it has two qualities:
//
// 1. It is well-supported on most operating systems without any additional
//    software, so anybody who finds themselves needing to deal with the
//    repository can inspect it in a reasonable way.
// 2. Files can be accessed in random order.
//
// We use the `rawzip` crate to deal with parsing the structures in a ZIP
// archive; any higher-level use cases are an exercise left to the consumer.
// This allows us to create a very strict ZIP archive reader. A list of common
// problems with using ZIP files, and the defenses we take:
//
// - Directory traversal, symlinks, and similar naughty file operations related
//   to extracting ZIP archives to a directory (e.g. "Zip Slip"). This module's
//   defense is to never extract any files to disk, avoiding recreating any
//   problems related to extraction. (The available API is to read specific
//   files in the archive as a stream.) Symlinks in ZIP files largely do not
//   work in the real world so they are ignored here (attempts to read a file
//   which is a symlink result in an error).
// - Central directory confusion due to differences in readers. APPNOTE.TXT is
//   full of doublespeak: one section says that archives must be read "from the
//   back" (starting from searching for the end-of-central-directory record),
//   and another suggests that archives can be streamed, or read "from the
//   front". `rawzip` always reads "from the back". Additionally, APPNOTE.TXT
//   arguably underspecifies comments, making it possible for the comment to
//   contain something that is misparsed as an end-of-central-directory record.
//   This module always expects the end-of-central-directory record to come at
//   the very end of the file, rejecting any archives that contain comments or
//   any extra content at the end.
//   https://web.archive.org/web/20250131021721/https://games.greggman.com/game/zip-rant/
// - Multiple entries with the same file name, leading to confusion due to
//   differences in readers. These are detected and those files return an error
//   if reading is attempted.
// - Quines and zip bombs which abuse overlapping file headers leading to a
//   denial of service. This module takes the defense suggested by `rawzip`,
//   which is to reject archives that contain files with overlapping file
//   data. We additionally reject archives where file data overlaps the central
//   directory.
//   https://www.bamsoftware.com/hacks/zipbomb/
// - Zip bombs which use extreme compression ratios leading to a denial of
//   service. This module takes no defense against this; instead this defense
//   is implemented in `tough`. The library places default size limits on
//   repository metadata, and all targets in the repository have a file size in
//   the signed metadata. A malicious archive designed to run a system out of
//   memory or temporary disk space would therefore also need to be signed and
//   trusted by the user (in the context of the Oxide control plane, this user
//   is either an administrator over the entire control plane, or has physical
//   access to the technician port).
//   https://docs.rs/tough/0.21.0/tough/struct.Limits.html

use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::sync::Arc;
use std::sync::LazyLock;

use bytes::Bytes;
use bytes::BytesMut;
use camino::Utf8PathBuf;
use flate2::read::DeflateDecoder;
use futures_util::Stream;
use rawzip::CompressionMethod;
use rawzip::FileReader;
use rawzip::ReaderAt;
use rawzip::ZipArchive;
use rawzip::ZipArchiveEntryWayfinder;
use rawzip::ZipFileHeaderRecord;
use slog::Logger;
use slog::error;
use slog::warn;
use tokio::sync::mpsc;
use tough::Transport;
use tough::TransportError;
use tough::TransportErrorKind;
use tough::TransportStream;
use tough::async_trait;
use url::Url;

use crate::error::Error;
use crate::error::ErrorKind;

macro_rules! try_archive_path {
    ($result:expr, $kind:ident, $path:expr) => {
        $crate::error::try_path!($result, $kind, archive_path: $path)
    };
}

// The length of the end-of-central-directory record if the comment is zero
// bytes. Archives with a "comment" (data after the EOCD) are rejected.
const EOCD_MAX_SEARCH_SPACE: u64 = 22;

/// Implementation of [`tough::Transport`] that operates on a Zip archive.
///
/// URLs used with this transport must use the `zip:///` protocol. For example,
/// if your metadata is found inside `repo/metadata` within the archive, use
/// `zip:///repo/metadata/` as the metadata base URL.
///
/// Convenience methods for setting the correct transport
/// and base URLs for loading Tufaceous-generated
/// repositories are [`RepositoryLoader::load_zip_buffer`] and
/// [`RepositoryLoader::load_zip_file`].
///
/// [`RepositoryLoader::load_zip_buffer`]: crate::RepositoryLoader::load_zip_buffer
/// [`RepositoryLoader::load_zip_file`]: crate::RepositoryLoader::load_zip_file
#[derive(Debug)]
pub struct ZipTransport<T: ReaderAt + Debug + Send + Sync + 'static> {
    inner: Arc<Inner<T>>,
    log: Logger,
}

#[derive(Debug)]
struct Inner<T: ReaderAt + Debug + Send + Sync + 'static> {
    archive: ZipArchive<T>,
    entries: HashMap<Url, Entry>,
}

// Manually implemented, as the derive macro adds an unnecessary `T: Clone`.
impl<T: ReaderAt + Debug + Send + Sync + 'static> Clone for ZipTransport<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), log: self.log.clone() }
    }
}

impl<T: AsRef<[u8]> + Debug + Send + Sync + 'static> ZipTransport<Cursor<T>> {
    pub fn from_slice(data: T, log: &Logger) -> Result<Self, Error> {
        let archive = ZipArchive::with_max_search_space(EOCD_MAX_SEARCH_SPACE)
            .locate_in_slice(data)
            .map_err(|(_, source)| ErrorKind::ReadZipEocd {
                source,
                archive_path: None,
            })?;
        Self::from_impl_blocking(archive.into_zip_archive(), None, None, log)
    }
}

impl ZipTransport<FileReader> {
    pub fn from_file_blocking(
        file: File,
        archive_path: Option<Utf8PathBuf>,
        log: &Logger,
    ) -> Result<Self, Error> {
        let mut buffer = vec![0; rawzip::RECOMMENDED_BUFFER_SIZE];
        let archive = try_archive_path!(
            ZipArchive::with_max_search_space(EOCD_MAX_SEARCH_SPACE)
                .locate_in_file(file, &mut buffer)
                .map_err(|(_, error)| error),
            ReadZipEocd,
            archive_path
        );
        Self::from_impl_blocking(archive, archive_path, Some(buffer), log)
    }
}

impl<T: ReaderAt + Debug + Send + Sync + 'static> ZipTransport<T> {
    fn from_impl_blocking(
        archive: ZipArchive<T>,
        archive_path: Option<Utf8PathBuf>,
        buffer: Option<Vec<u8>>,
        log: &Logger,
    ) -> Result<Self, Error> {
        let mut buffer =
            buffer.unwrap_or_else(|| vec![0; rawzip::RECOMMENDED_BUFFER_SIZE]);

        let mut entries = HashMap::new();
        // Keep a list of all central directory entries (regardless of whether
        // the path is valid) to check for an unexpected number of entries, or
        // overlapping file ranges.
        let mut all_entries = Vec::new();

        let mut records = archive.entries(&mut buffer);
        while let Some(record) =
            try_archive_path!(records.next_entry(), ReadZipCdfh, archive_path)
        {
            if usize64!(all_entries.len()) >= archive.entries_hint() {
                return Err(ErrorKind::ZipEntryCount {
                    expected: archive.entries_hint(),
                    actual: None,
                    archive_path,
                }
                .into());
            }

            all_entries.push(RawEntry::from(&record));
            if let Some((url, entry)) = Entry::new(&record, log) {
                entries
                    .entry(url)
                    .and_modify(|e| *e = Entry::Duplicate)
                    .or_insert(entry);
            }
        }

        // First check: the number of entries in the central directory matches
        // the value in the EOCD record.
        let actual = usize64!(all_entries.len());
        if archive.entries_hint() != actual {
            return Err(ErrorKind::ZipEntryCount {
                expected: archive.entries_hint(),
                actual: Some(actual),
                archive_path,
            }
            .into());
        }

        let mut ranges = Vec::new();
        for RawEntry { raw_path, wayfinder } in all_entries {
            let entry = try_archive_path!(
                archive.get_entry(wayfinder),
                ReadZipLocal,
                archive_path
            );
            let header = try_archive_path!(
                entry.local_header(&mut buffer),
                ReadZipLocal,
                archive_path
            );
            // Check that the path in the central directory matches the header
            // that comes before the file data range.
            if raw_path != header.file_path().as_bytes() {
                return Err(ErrorKind::ZipPathMismatch {
                    central: raw_path,
                    local: header.file_path().as_bytes().to_vec(),
                    archive_path,
                }
                .into());
            }

            let (start, end) = entry.compressed_data_range();
            ranges.push((start..end, raw_path));
            // Check that no file ranges overlap with or come after the central
            // directory.
            if end > archive.directory_offset() {
                return Err(ErrorKind::ZipRangeOverrun {
                    file_path: header.file_path().as_bytes().to_vec(),
                    data_range: start..end,
                    archive_path,
                }
                .into());
            }
        }
        // Check that no file ranges overlap with each other.
        ranges.sort_by_key(|(range, _)| range.start);
        for [(earlier, earlier_path), (later, later_path)] in
            ranges.array_windows()
        {
            if earlier.end > later.start {
                return Err(ErrorKind::ZipOverlappingRanges {
                    earlier_path: earlier_path.clone(),
                    earlier: earlier.clone(),
                    later_path: later_path.clone(),
                    later: later.clone(),
                    archive_path,
                }
                .into());
            }
        }

        Ok(Self {
            inner: Arc::new(Inner { archive, entries }),
            log: log.clone(),
        })
    }

    fn stream(
        self,
        entry_data: EntryData,
        url: Url,
    ) -> impl Stream<Item = Result<Bytes, TransportError>> {
        // This could be a lot nicer but the ZIP entry reader can't cross in/out
        // of `spawn_blocking` because the type has an associated lifetime.
        let (tx, mut rx) = mpsc::channel::<Result<Bytes, TransportError>>(1);
        let cloned_url = url.clone();
        let task = tokio::task::spawn_blocking(move || {
            type SendError =
                mpsc::error::SendError<Result<Bytes, TransportError>>;

            let mut reader = match self
                .inner
                .archive
                .get_entry(entry_data.wayfinder)
                .map_err(ZipTransportError::from)
                .and_then(|entry| match entry_data.compression_method {
                    CompressionMethod::Store => Ok(entry.verifying_reader(
                        Box::new(entry.reader()) as Box<dyn Read>,
                    )),
                    CompressionMethod::Deflate => Ok(entry.verifying_reader(
                        Box::new(DeflateDecoder::new(entry.reader())),
                    )),
                    other => Err(ZipTransportError::CompressionMethod(other)),
                }) {
                Ok(reader) => reader,
                Err(error) => {
                    tx.blocking_send(Err(error.into_tough_error(url)))?;
                    return Ok::<_, SendError>(());
                }
            };

            let mut buf = BytesMut::with_capacity(8192);
            loop {
                if buf.capacity() == 0 {
                    buf.reserve(8192);
                }
                buf.resize(buf.capacity(), 0);
                match reader.read(&mut buf) {
                    Ok(0) => return Ok::<_, SendError>(()),
                    Ok(n) => {
                        buf.truncate(n);
                        tx.blocking_send(Ok(buf.split().freeze()))?;
                    }
                    Err(error) => {
                        tx.blocking_send(Err(ZipTransportError::from(error)
                            .into_tough_error(url)))?;
                        return Ok::<_, SendError>(());
                    }
                }
            }
        });

        tokio::task::spawn(async move {
            if let Ok(Err(send_error)) = task.await {
                match send_error.0 {
                    Ok(_) => {
                        error!(
                            self.log,
                            "zip file reader hung up mid-stream";
                            "url" => &cloned_url.to_string(),
                        );
                    }
                    Err(err) => {
                        error!(
                            self.log,
                            "zip file reader hung up mid-stream \
                            before receiving error";
                            "url" => &cloned_url.to_string(),
                            "err" => &crate::util::error_chain(&err),
                        );
                    }
                }
            }
        });
        futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
    }
}

#[async_trait]
impl<T: ReaderAt + Debug + Send + Sync + 'static> Transport
    for ZipTransport<T>
{
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        if url.scheme() != "zip" {
            return Err(TransportError::new(
                TransportErrorKind::UnsupportedUrlScheme,
                url,
            ));
        }
        match self.inner.entries.get(&url).copied() {
            Some(Entry::File(entry_data)) => {
                Ok(Box::pin(self.clone().stream(entry_data, url)))
            }
            Some(Entry::Dir) => {
                Err(ZipTransportError::IsADirectory.into_tough_error(url))
            }
            Some(Entry::Symlink) => {
                Err(ZipTransportError::IsASymlink.into_tough_error(url))
            }
            Some(Entry::Duplicate) => {
                Err(ZipTransportError::Duplicate.into_tough_error(url))
            }
            None => Err(ZipTransportError::FileNotFound.into_tough_error(url)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Entry {
    File(EntryData),
    Dir,
    Symlink,
    Duplicate,
}

#[derive(Debug, Clone, Copy)]
struct EntryData {
    compression_method: CompressionMethod,
    wayfinder: ZipArchiveEntryWayfinder,
}

impl Entry {
    fn new(
        record: &ZipFileHeaderRecord<'_>,
        log: &Logger,
    ) -> Option<(Url, Self)> {
        static BASE_URL: LazyLock<Url> = LazyLock::new(|| {
            Url::parse("zip:///").expect("`zip:///` is a valid URL")
        });

        let path = record.file_path();
        let path = path
            .try_normalize()
            .inspect_err(|err| {
                warn!(
                    log,
                    "ignoring invalid path in zip archive";
                    "path" => path.as_bytes().escape_ascii().to_string(),
                    "error" => err.to_string(),
                );
            })
            .ok()?;
        let url = BASE_URL
            .join(path.as_str())
            .inspect_err(|err| {
                warn!(
                    log,
                    "ignoring invalid path in zip archive";
                    "path" => path.as_str(),
                    "error" => err.to_string(),
                );
            })
            .ok()?;

        let entry = if record.is_dir() {
            Entry::Dir
        } else if record.mode().is_symlink() {
            Entry::Symlink
        } else {
            Entry::File(EntryData {
                compression_method: record.compression_method(),
                wayfinder: record.wayfinder(),
            })
        };

        Some((url, entry))
    }
}

#[derive(Debug)]
struct RawEntry {
    raw_path: Vec<u8>,
    wayfinder: ZipArchiveEntryWayfinder,
}

impl<'a> From<&'a ZipFileHeaderRecord<'a>> for RawEntry {
    fn from(record: &'a ZipFileHeaderRecord<'a>) -> Self {
        Self {
            raw_path: record.file_path().as_bytes().to_vec(),
            wayfinder: record.wayfinder(),
        }
    }
}

/// Possible source errors of [`ZipTransport::fetch`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ZipTransportError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
    #[error("failed to join {url} onto {base}")]
    UrlJoin { source: url::ParseError, url: String, base: String },
    #[error(transparent)]
    Zip(#[from] rawzip::Error),

    #[error("unsupported compression method {0:?}")]
    CompressionMethod(CompressionMethod),
    #[error("multiple entries found for file")]
    Duplicate,
    #[error("file not found")]
    FileNotFound,
    #[error("is a directory")]
    IsADirectory,
    #[error("is a symlink")]
    IsASymlink,
}

impl ZipTransportError {
    fn into_tough_error(self, url: Url) -> TransportError {
        let kind = match &self {
            ZipTransportError::FileNotFound => TransportErrorKind::FileNotFound,

            ZipTransportError::Io(_)
            | ZipTransportError::Join(_)
            | ZipTransportError::UrlJoin { .. }
            | ZipTransportError::Zip(_)
            | ZipTransportError::CompressionMethod(_)
            | ZipTransportError::Duplicate
            | ZipTransportError::IsADirectory
            | ZipTransportError::IsASymlink => TransportErrorKind::Other,
        };
        TransportError::new_with_cause(kind, url, self)
    }
}
