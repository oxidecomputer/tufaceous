// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::sync::Arc;

use bytes::Bytes;
use bytes::BytesMut;
use camino::Utf8PathBuf;
use flate2::read::DeflateDecoder;
use futures_util::FutureExt;
use futures_util::Stream;
use futures_util::StreamExt;
use futures_util::stream;
use rawzip::CompressionMethod;
use rawzip::FileReader;
use rawzip::ReaderAt;
use rawzip::ZipArchive;
use rawzip::ZipArchiveEntryWayfinder;
use rawzip::path::RawPath;
use rawzip::path::ZipFilePath;
use slog::Logger;
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

/// Implementation of [`tough::Transport`] that operates on a Zip archive.
///
/// URLs used with this transport must use the `zip:///` protocol. For example,
/// if your metadata is found inside `repo/metadata` within the archive, use
/// `zip:///repo/metadata/` as the metadata base URL.
///
/// Convenience methods for setting the correct transport
/// and base URLs for loading Tufaceous-generated
/// repositories are [`RepositoryLoader::load_zip_slice`] and
/// [`RepositoryLoader::load_zip_file`].
///
/// [`RepositoryLoader::load_zip_slice`]: [`crate::RepositoryLoader::load_zip_slice`]
/// [`RepositoryLoader::load_zip_file`]: [`crate::RepositoryLoader::load_zip_file`]
#[derive(Debug)]
pub struct ZipTransport<T: ReaderAt + Debug + Send + Sync + 'static> {
    inner: Arc<Inner<T>>,
}

#[derive(Debug)]
struct Inner<T: ReaderAt + Debug + Send + Sync + 'static> {
    archive: ZipArchive<T>,
    entries: HashMap<Url, Entry>,
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

// Manually implemented, as the derive macro adds an unnecessary `T: Clone`.
impl<T: ReaderAt + Debug + Send + Sync + 'static> Clone for ZipTransport<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<T: AsRef<[u8]> + Debug + Send + Sync + 'static> ZipTransport<Cursor<T>> {
    pub fn from_slice(data: T, log: &Logger) -> Result<Self, Error> {
        let archive = ZipArchive::from_slice(data).upgrade(None)?;
        Self::from_impl_blocking(archive.into_zip_archive(), None, None, log)
    }
}

impl ZipTransport<FileReader> {
    pub async fn from_file(
        file: File,
        archive_path: Option<Utf8PathBuf>,
        log: &Logger,
    ) -> Result<Self, Error> {
        let log = log.clone();
        tokio::task::spawn_blocking(move || {
            let archive_path = archive_path;
            let mut buffer = vec![0; rawzip::RECOMMENDED_BUFFER_SIZE];
            let archive = ZipArchive::from_file(file, &mut buffer)
                .upgrade(archive_path.as_ref())?;
            Self::from_impl_blocking(archive, archive_path, Some(buffer), &log)
        })
        .await?
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
        let expected = archive.entries_hint();
        let mut actual: u64 = 0;
        let mut all_entries = Vec::new();
        let mut entries = HashMap::new();
        let mut records = archive.entries(&mut buffer);
        while let Some(record) =
            records.next_entry().upgrade(archive_path.as_ref())?
        {
            actual += 1;
            all_entries.push((
                record.wayfinder(),
                record.file_path().as_bytes().to_vec(),
            ));

            let Some(url) = path_to_url(record.file_path(), log) else {
                continue;
            };
            match entries.entry(url) {
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    e.insert(Entry::Duplicate);
                }
                std::collections::hash_map::Entry::Vacant(e) => {
                    if record.is_dir() {
                        e.insert(Entry::Dir);
                    } else if record.mode().is_symlink() {
                        e.insert(Entry::Symlink);
                    } else {
                        let data = EntryData {
                            compression_method: record.compression_method(),
                            wayfinder: record.wayfinder(),
                        };
                        e.insert(Entry::File(data));
                    }
                }
            }
        }

        if expected != actual {
            return Err(ErrorKind::ZipEntryCount {
                expected,
                actual,
                archive_path,
            }
            .into());
        }

        let mut ranges = Vec::new();
        for (wayfinder, raw_path) in all_entries {
            let entry =
                archive.get_entry(wayfinder).upgrade(archive_path.as_ref())?;
            let header = entry
                .local_header(&mut buffer)
                .upgrade(archive_path.as_ref())?;
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
        for window in ranges.windows(2) {
            let [(earlier, earlier_path), (later, later_path)] = window else {
                panic!("slice::windows is broken")
            };
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

        Ok(Self { inner: Arc::new(Inner { archive, entries }) })
    }

    fn stream(
        self,
        entry_data: EntryData,
        url: Url,
    ) -> impl Stream<Item = Result<Bytes, TransportError>> {
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::task::spawn_blocking(move || {
            let entry = self.inner.archive.get_entry(entry_data.wayfinder)?;
            let mut reader = match entry_data.compression_method {
                CompressionMethod::Store => {
                    let reader = entry.reader();
                    Box::new(entry.verifying_reader(reader)) as Box<dyn Read>
                }
                CompressionMethod::Deflate => {
                    let reader = DeflateDecoder::new(entry.reader());
                    Box::new(entry.verifying_reader(reader)) as Box<dyn Read>
                }
                other => {
                    return Err(ZipTransportError::CompressionMethod(other));
                }
            };

            let mut buf = BytesMut::zeroed(8192);
            while let n = reader.read(&mut buf)?
                && n > 0
            {
                buf.truncate(n);
                let Ok(()) = tx.blocking_send(buf.split().freeze()) else {
                    break;
                };
                if buf.capacity() == 0 {
                    buf.reserve(8192);
                }
                buf.resize(buf.capacity(), 0);
            }
            Ok::<_, ZipTransportError>(())
        });
        stream::poll_fn(move |cx| rx.poll_recv(cx)).map(Ok).chain(
            task.into_stream().filter_map(move |result| {
                let error = match result {
                    Ok(Ok(())) => return std::future::ready(None),
                    Ok(Err(error)) => error,
                    Err(join_error) => join_error.into(),
                };
                std::future::ready(Some(Err(error.upgrade(url.clone()))))
            }),
        )
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
                Err(ZipTransportError::IsADirectory.upgrade(url))
            }
            Some(Entry::Symlink) => {
                Err(ZipTransportError::IsASymlink.upgrade(url))
            }
            Some(Entry::Duplicate) => {
                Err(ZipTransportError::Duplicate.upgrade(url))
            }
            None => Err(ZipTransportError::FileNotFound.upgrade(url)),
        }
    }
}

trait ResultExt<T> {
    fn upgrade(self, archive_path: Option<&Utf8PathBuf>) -> Result<T, Error>;
}

impl<T> ResultExt<T> for Result<T, rawzip::Error> {
    fn upgrade(self, archive_path: Option<&Utf8PathBuf>) -> Result<T, Error> {
        match self {
            Ok(v) => Ok(v),
            Err(source) => Err(ErrorKind::ReadZip {
                source,
                archive_path: archive_path.cloned(),
            })?,
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
    fn upgrade(self, url: Url) -> TransportError {
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

fn path_to_url(path: ZipFilePath<RawPath<'_>>, log: &Logger) -> Option<Url> {
    path.try_normalize()
        .inspect_err(|err| {
            warn!(
                log,
                "ignoring invalid path in zip archive";
                "path" => path.as_bytes().escape_ascii().to_string(),
                "error" => err.to_string(),
            );
        })
        .ok()
        .and_then(|path| {
            Url::parse("zip:///")
                .expect("`zip:///` is a valid URL")
                .join(path.as_str())
                .inspect_err(|err| {
                    warn!(
                        log,
                        "ignoring invalid path in zip archive";
                        "path" => path.as_str(),
                        "error" => err.to_string(),
                    );
                })
                .ok()
        })
}
