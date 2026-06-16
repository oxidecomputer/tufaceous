// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::Write;
use std::num::NonZero;
use std::time::Duration;

use atomicwrites::AtomicFile;
use atomicwrites::OverwriteBehavior;
use bytes::Bytes;
use camino::Utf8Path;
use camino::Utf8PathBuf;
use chrono::DateTime;
use chrono::SubsecRound;
use chrono::Utc;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use futures_util::StreamExt;
use futures_util::TryStreamExt;
use rawzip::CompressionMethod;
use rawzip::ZipArchiveWriter;
use rawzip::time::UtcDateTime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tough::key_source::KeySource;
use tough::schema::Root;
use tough::schema::Signed;

use crate::edit::Ed25519Key;
use crate::edit::OXIDE_BOOT_MAGIC;
use crate::edit::source::FileSource;
use crate::edit::source::Target;
use crate::edit::source::TargetSource;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::error::try_path;

pub(crate) const DEFAULT_VALIDITY: Duration =
    Duration::from_secs(60 * 60 * 24 * 7 /* 1 week */);

#[derive(Debug)]
#[must_use]
pub struct UnsignedRepository<'a> {
    targets: BTreeMap<String, Target<'a>>,
    root: Option<RequestedRoot>,
    keys: Vec<Box<dyn KeySource>>,
    snapshot_version: NonZero<u64>,
    snapshot_expires: DateTime<Utc>,
    targets_version: NonZero<u64>,
    targets_expires: DateTime<Utc>,
    timestamp_version: NonZero<u64>,
    timestamp_expires: DateTime<Utc>,
}

#[derive(Debug)]
enum RequestedRoot {
    Root(Vec<u8>),
    Generate,
}

impl<'a> UnsignedRepository<'a> {
    pub(crate) fn from_targets(targets: BTreeMap<String, Target<'a>>) -> Self {
        let now = Utc::now().trunc_subsecs(0);
        let version = NonZero::try_from(now.timestamp())
            .and_then(NonZero::<u64>::try_from)
            .unwrap_or(NonZero::<u64>::MIN);
        let expires = now + DEFAULT_VALIDITY;

        Self {
            targets,
            root: None,
            keys: Vec::new(),
            snapshot_version: version,
            snapshot_expires: expires,
            targets_version: version,
            targets_expires: expires,
            timestamp_version: version,
            timestamp_expires: expires,
        }
    }

    pub fn root(self, root: impl AsRef<[u8]>) -> Self {
        Self { root: Some(RequestedRoot::Root(root.as_ref().to_vec())), ..self }
    }

    pub fn key(mut self, key: impl KeySource + 'static) -> Self {
        self.keys.push(Box::new(key));
        self
    }

    pub fn generate_root(self) -> Self {
        Self { root: Some(RequestedRoot::Generate), ..self }
    }

    pub fn snapshot_version(self, snapshot_version: NonZero<u64>) -> Self {
        Self { snapshot_version, ..self }
    }

    pub fn snapshot_expires(self, snapshot_expires: DateTime<Utc>) -> Self {
        Self { snapshot_expires, ..self }
    }

    pub fn targets_version(self, targets_version: NonZero<u64>) -> Self {
        Self { targets_version, ..self }
    }

    pub fn targets_expires(self, targets_expires: DateTime<Utc>) -> Self {
        Self { targets_expires, ..self }
    }

    pub fn timestamp_version(self, timestamp_version: NonZero<u64>) -> Self {
        Self { timestamp_version, ..self }
    }

    pub fn timestamp_expires(self, timestamp_expires: DateTime<Utc>) -> Self {
        Self { timestamp_expires, ..self }
    }

    pub async fn sign(mut self) -> Result<SignedRepository<'a>, Error> {
        let (root, consistent_snapshot) = match self.root {
            Some(RequestedRoot::Root(root)) => {
                let parsed_root: Signed<Root> =
                    serde_json::from_slice(&root)
                        .map_err(ErrorKind::ParseSigningRoot)?;
                (root, parsed_root.signed.consistent_snapshot)
            }
            Some(RequestedRoot::Generate) => {
                if self.keys.is_empty() {
                    self.keys.push(Box::new(Ed25519Key::generate()?));
                }
                let expires = self
                    .snapshot_expires
                    .min(self.targets_expires)
                    .min(self.timestamp_expires);
                let root =
                    crate::edit::generate_root(&self.keys, expires).await?;
                (
                    root.buffer().clone(),
                    root.signed().signed.consistent_snapshot,
                )
            }
            None => return Err(ErrorKind::NoSigningRoot.into()),
        };

        let tempdir = tokio::task::spawn_blocking(camino_tempfile::tempdir)
            .await?
            .map_err(ErrorKind::CreateTempDir)?;

        // tough's RepositoryEditor can only be constructed with a path to a
        // root role, which is mildly silly; we need to write the root out to a
        // temporary directory so it can read it back in again.
        let root_path = tempdir.path().join("root.json");
        try_path!(
            tokio::fs::write(&root_path, &root).await,
            WriteFile,
            root_path
        );
        let mut editor =
            tough::editor::RepositoryEditor::new(&root_path).await?;
        editor
            .snapshot_version(self.snapshot_version)
            .snapshot_expires(self.snapshot_expires)
            .targets_version(self.targets_version)?
            .targets_expires(self.targets_expires)?
            .timestamp_version(self.timestamp_version)
            .timestamp_expires(self.timestamp_expires);

        let mut sources = BTreeMap::new();
        for (target_name, Target { length, sha256, source }) in self.targets {
            let path = if consistent_snapshot {
                format!("{}.{target_name}", hex::encode(sha256))
            } else {
                target_name.clone()
            };
            let hashes = tough::schema::Hashes {
                sha256: sha256.0.to_vec().into(),
                _extra: HashMap::new(),
            };
            let target = tough::schema::Target {
                length,
                hashes,
                custom: HashMap::new(),
                _extra: HashMap::new(),
            };
            editor.add_target(target_name.as_str(), target)?;

            sources.insert((FilePrefix::Targets, path), source);
        }

        let signed = editor.sign(&self.keys).await?;
        // We can't read the metadata directly, so we again need to write it to
        // our temporary directory and then read the data back in.
        let metadata_dir = tempdir.path().join("metadata");
        signed.write(&metadata_dir).await?;
        let mut read_dir = crate::util::read_dir(metadata_dir).await?;
        while let Some(entry) = read_dir.try_next().await? {
            // This is opening a file within the tempdir that is about to be
            // deleted. This is expected to be fine.
            let source =
                FileSource::open(entry.path().to_owned()).await?.into();
            sources.insert(
                (FilePrefix::Metadata, entry.file_name().into()),
                source,
            );
        }

        Ok(SignedRepository { root, sources })
    }
}

#[derive(Debug)]
pub struct SignedRepository<'a> {
    root: Vec<u8>,
    sources: BTreeMap<(FilePrefix, String), TargetSource<'a>>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FilePrefix {
    Metadata,
    Targets,
}

impl SignedRepository<'_> {
    pub fn root(&self) -> &[u8] {
        &self.root
    }

    pub async fn write_zip<W: Write + Send + 'static>(
        &self,
        writer: W,
        modification_time: DateTime<Utc>,
    ) -> Result<W, Error> {
        let (tx, rx) = mpsc::channel(1);
        let task = tokio::task::spawn_blocking(move || {
            blocking_write_task(writer, rx, modification_time)
        });
        self.write_zip_impl(tx, task, None).await
    }

    pub async fn write_zip_file(
        &self,
        path: impl AsRef<Utf8Path>,
        modification_time: DateTime<Utc>,
    ) -> Result<(), Error> {
        let path = path.as_ref();
        let file = AtomicFile::new(path, OverwriteBehavior::AllowOverwrite);
        let (tx, rx) = mpsc::channel(1);
        let task = tokio::task::spawn_blocking(move || {
            file.write(|file| {
                blocking_write_task(file, rx, modification_time).map(|_| ())
            })?;
            Ok(())
        });
        self.write_zip_impl(tx, task, Some(path)).await
    }

    async fn write_zip_impl<W>(
        &self,
        tx: mpsc::Sender<ZipWriterMessage>,
        task: JoinHandle<Result<W, ZipWriterError>>,
        archive_path: Option<&Utf8Path>,
    ) -> Result<W, Error> {
        'outer: for ((prefix, name), source) in &self.sources {
            let prefix = Utf8Path::new(match prefix {
                FilePrefix::Metadata => "repo/metadata",
                FilePrefix::Targets => "repo/targets",
            });
            let mut stream = source.stream();
            let first_chunk = stream.try_next().await?;
            let compression = first_chunk
                .as_deref()
                .map_or(Compression::none(), deflate_heuristic);

            let Ok(()) = tx
                .send(ZipWriterMessage::StartFile {
                    name: prefix.join(name),
                    compression,
                })
                .await
            else {
                break 'outer;
            };

            let mut stream =
                futures_util::stream::iter(first_chunk).map(Ok).chain(stream);
            while let Some(chunk) = stream.try_next().await? {
                let Ok(()) =
                    tx.send(ZipWriterMessage::WriteFileBytes(chunk)).await
                else {
                    break 'outer;
                };
            }
            let Ok(()) = tx.send(ZipWriterMessage::FinishFile).await else {
                break 'outer;
            };
        }
        tx.send(ZipWriterMessage::FinishArchive).await.ok();
        task.await?.map_err(|error| {
            let source = match error {
                ZipWriterError::Zip(error) => error,
                err @ (ZipWriterError::ExpectedFile
                | ZipWriterError::ExpectedBytes) => {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, err)
                        .into()
                }
                err @ ZipWriterError::UnexpectedEof => {
                    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, err)
                        .into()
                }
            };
            ErrorKind::WriteZip {
                source,
                archive_path: archive_path.map(Utf8Path::to_owned),
            }
            .into()
        })
    }
}

fn deflate_heuristic(buf: &[u8]) -> Compression {
    if buf.is_empty() {
        // probably an empty file!
        Compression::none()
    } else if buf.starts_with(b"\x1f\x8b") {
        // gzip, e.g. illumos zone tarball
        Compression::none()
    } else if buf.starts_with(b"\x78")
        && let Some([x, y]) = &buf.get(..2)
        && u16::from_be_bytes([*x, *y]) % 31 == 0
    {
        // zlib
        if y & 0xc0 == 0 {
            // buf is zlib-compressed at level 0, which is not compressed at
            // all, so we should compress this
            Compression::best()
        } else {
            Compression::none()
        }
    } else if buf.starts_with(b"PK\x03\x04") {
        // ZIP archive, e.g. hubris archive. not necessarily compressed based on
        // this heuristic alone but in our case it's very likely.
        Compression::none()
    } else if buf.starts_with(&OXIDE_BOOT_MAGIC) {
        // oxide phase 2 OS image. images are zlib-compressed after the header
        // if the least-significant bit of the flags starting at byte 8 is set:
        if buf.get(8).is_some_and(|b| *b & 0x1 == 0x1) {
            Compression::none()
        } else {
            // not zlib-compressed, but the ZFS dataset likely has compression
            // enabled. use fast compression to deflate unused blocks
            Compression::fast()
        }
    } else {
        Compression::best()
    }
}

enum ZipWriterMessage {
    FinishArchive,
    StartFile { name: Utf8PathBuf, compression: Compression },
    WriteFileBytes(Bytes),
    FinishFile,
}

#[derive(Debug, thiserror::Error)]
enum ZipWriterError {
    #[error(transparent)]
    Zip(#[from] rawzip::Error),
    #[error("state machine violation: expected file start or archive finish")]
    ExpectedFile,
    #[error("state machine violation: expected file bytes or file finish")]
    ExpectedBytes,
    #[error("state machine violation: unexpected end of message stream")]
    UnexpectedEof,
}

impl From<std::io::Error> for ZipWriterError {
    fn from(error: std::io::Error) -> Self {
        ZipWriterError::Zip(error.into())
    }
}

impl From<atomicwrites::Error<ZipWriterError>> for ZipWriterError {
    fn from(error: atomicwrites::Error<ZipWriterError>) -> Self {
        match error {
            atomicwrites::Error::User(error) => error,
            atomicwrites::Error::Internal(error) => error.into(),
        }
    }
}

fn blocking_write_task<W: Write>(
    writer: W,
    mut rx: mpsc::Receiver<ZipWriterMessage>,
    modification_time: DateTime<Utc>,
) -> Result<W, ZipWriterError> {
    let mut archive = ZipArchiveWriter::new(writer);
    loop {
        let message =
            rx.blocking_recv().ok_or(ZipWriterError::UnexpectedEof)?;
        let (name, compression) = match message {
            ZipWriterMessage::FinishArchive => {
                return Ok(archive.finish()?);
            }
            ZipWriterMessage::StartFile { name, compression } => {
                (name, compression)
            }
            ZipWriterMessage::WriteFileBytes(_)
            | ZipWriterMessage::FinishFile => {
                return Err(ZipWriterError::ExpectedFile);
            }
        };

        let (mut entry, config) = archive
            .new_file(name.as_str())
            .compression_method(if compression == Compression::none() {
                CompressionMethod::Store
            } else {
                CompressionMethod::Deflate
            })
            .last_modified(UtcDateTime::from_unix(
                modification_time.timestamp(),
            ))
            .unix_permissions(0o644)
            .start()?;
        let encoder = ZipEncoder::new(&mut entry, compression);
        let mut writer = config.wrap(encoder);

        loop {
            let message =
                rx.blocking_recv().ok_or(ZipWriterError::UnexpectedEof)?;
            match message {
                ZipWriterMessage::WriteFileBytes(bytes) => {
                    writer.write_all(&bytes)?;
                }
                ZipWriterMessage::FinishFile => {
                    let (encoder, output) = writer.finish()?;
                    encoder.finish()?;
                    entry.finish(output)?;
                    break;
                }
                ZipWriterMessage::FinishArchive
                | ZipWriterMessage::StartFile { .. } => {
                    return Err(ZipWriterError::ExpectedBytes);
                }
            }
        }
    }
}

enum ZipEncoder<W: Write> {
    Store(W),
    Deflate(DeflateEncoder<W>),
}

impl<W: Write> ZipEncoder<W> {
    fn new(writer: W, compression: Compression) -> Self {
        if compression == Compression::none() {
            Self::Store(writer)
        } else {
            Self::Deflate(DeflateEncoder::new(writer, compression))
        }
    }

    fn finish(self) -> std::io::Result<W> {
        match self {
            Self::Store(writer) => Ok(writer),
            Self::Deflate(encoder) => encoder.finish(),
        }
    }
}

impl<W: Write> Write for ZipEncoder<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ZipEncoder::Store(writer) => writer.write(buf),
            ZipEncoder::Deflate(writer) => writer.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ZipEncoder::Store(writer) => writer.flush(),
            ZipEncoder::Deflate(writer) => writer.flush(),
        }
    }
}
