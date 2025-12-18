// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::Write;
use std::num::NonZero;
use std::time::Duration;

use camino::Utf8Path;
use chrono::DateTime;
use chrono::SubsecRound;
use chrono::Utc;
use flate2::Compression;
use futures_util::TryStreamExt;
use rawzip::time::UtcDateTime;
use tough::key_source::KeySource;
use tough::schema::Root;
use tough::schema::Signed;

use crate::edit::Ed25519Key;
use crate::edit::source::FileSource;
use crate::edit::source::Target;
use crate::edit::source::TargetSource;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::zip_writer::ZipWriter;

pub(crate) const DEFAULT_VALIDITY: Duration =
    Duration::from_secs(60 * 60 * 24 * 7 /* 1 week */);

#[derive(Debug)]
pub struct UnsignedRepository<'a> {
    targets: BTreeMap<String, Target<'a>>,
    root: Option<Vec<u8>>,
    keys: Vec<Box<dyn KeySource>>,
    generate_root: bool,
    snapshot_version: NonZero<u64>,
    snapshot_expires: DateTime<Utc>,
    targets_version: NonZero<u64>,
    targets_expires: DateTime<Utc>,
    timestamp_version: NonZero<u64>,
    timestamp_expires: DateTime<Utc>,
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
            generate_root: false,
            snapshot_version: version,
            snapshot_expires: expires,
            targets_version: version,
            targets_expires: expires,
            timestamp_version: version,
            timestamp_expires: expires,
        }
    }

    pub fn root(self, root: impl AsRef<[u8]>) -> Self {
        Self {
            root: Some(root.as_ref().to_vec()),
            generate_root: false,
            ..self
        }
    }

    pub fn key(mut self, key: impl KeySource + 'static) -> Self {
        self.keys.push(Box::new(key));
        self
    }

    pub fn generate_root(self) -> Self {
        Self { root: None, generate_root: true, ..self }
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
        let (root, consistent_snapshot) = if let Some(root) = self.root {
            let parsed_root: Signed<Root> = serde_json::from_slice(&root)
                .map_err(ErrorKind::ParseSigningRoot)?;
            (root, parsed_root.signed.consistent_snapshot)
        } else if self.generate_root {
            if self.keys.is_empty() {
                self.keys.push(Box::new(Ed25519Key::generate()?));
            }
            let expires = self
                .snapshot_expires
                .min(self.targets_expires)
                .min(self.timestamp_expires);
            let root = crate::edit::generate_root(&self.keys, expires).await?;
            (root.buffer().clone(), root.signed().signed.consistent_snapshot)
        } else {
            return Err(ErrorKind::NoSigningRoot.into());
        };

        let tempdir = tokio::task::spawn_blocking(camino_tempfile::tempdir)
            .await?
            .map_err(ErrorKind::CreateTempDir)?;

        // tough's RepositoryEditor can only be constructed with a path to a
        // root role, which is mildly silly; we need to write the root out to a
        // temporary directory so it can read it back in again.
        let root_path = tempdir.path().join("root.json");
        tokio::fs::write(&root_path, &root).await.map_err(|source| {
            ErrorKind::WriteFile { source, path: root_path.clone() }
        })?;
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
                format!("{}.{target_name}", hex::encode(&sha256))
            } else {
                target_name.clone()
            };
            let hashes = tough::schema::Hashes {
                sha256: sha256.into(),
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
                TargetSource::File(FileSource::open(entry.path()).await?);
            sources.insert(
                (FilePrefix::Metadata, entry.file_name().into()),
                source,
            );
        }

        Ok(SignedRepository { sources })
    }
}

#[derive(Debug)]
pub struct SignedRepository<'a> {
    sources: BTreeMap<(FilePrefix, String), TargetSource<'a>>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FilePrefix {
    Metadata,
    Targets,
}

impl SignedRepository<'_> {
    pub async fn write_zip<W: Write + Send + 'static>(
        &mut self,
        writer: W,
        modification_time: DateTime<Utc>,
    ) -> Result<W, Error> {
        self.write_zip_impl(ZipWriter::new(writer), modification_time, None)
            .await
    }

    pub async fn write_zip_file(
        &mut self,
        path: impl AsRef<Utf8Path>,
        modification_time: DateTime<Utc>,
    ) -> Result<(), Error> {
        let path = path.as_ref();
        self.write_zip_impl(
            ZipWriter::create(path),
            modification_time,
            Some(path),
        )
        .await
    }

    async fn write_zip_impl<W>(
        &mut self,
        mut writer: ZipWriter<W>,
        modification_time: DateTime<Utc>,
        archive_path: Option<&Utf8Path>,
    ) -> Result<W, Error> {
        let last_modified =
            UtcDateTime::from_unix(modification_time.timestamp());
        'outer: for ((prefix, name), source) in &mut self.sources {
            let prefix = Utf8Path::new(match prefix {
                FilePrefix::Metadata => "repo/metadata",
                FilePrefix::Targets => "repo/targets",
            });
            let mut stream = source.stream();
            let first_chunk = stream.try_next().await?;
            let compression = first_chunk
                .as_deref()
                .map_or(Compression::none(), deflate_heuristic);
            let Ok(mut entry) = writer
                .new_file(prefix.join(name))
                .compression(compression)
                .last_modified(last_modified)
                .unix_permissions(0o644)
                .start()
                .await
            else {
                break 'outer;
            };
            let Some(first_chunk) = first_chunk else { continue };
            let Ok(()) = entry.write(first_chunk).await else { break };
            while let Some(item) = stream.try_next().await? {
                let Ok(()) = entry.write(item).await else { break 'outer };
            }
        }
        writer.finish().await.map_err(|source| {
            let archive_path = archive_path.map(|p| p.to_owned());
            ErrorKind::WriteZip { source, archive_path }.into()
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
    } else if buf.starts_with(b"PK\x03\x04") {
        // ZIP archive, e.g. hubris archive. not necessarily compressed based on
        // this heuristic alone but in our case it's very likely.
        Compression::none()
    } else if buf.starts_with(&0x1DEB0075_u32.to_le_bytes()) {
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
