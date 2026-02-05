// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::io::BufRead;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;

use bytes::Buf;
use bytes::Bytes;
use bytes::BytesMut;
use camino::FromPathBufError;
use camino::Utf8PathBuf;
use flate2::bufread::GzDecoder;
use futures_util::Stream;
use futures_util::TryStreamExt;
use futures_util::pin_mut;
use futures_util::stream;
use hubtools::Caboose;
use hubtools::RawHubrisArchive;
use rawzip::FileReader;
use rawzip::RangeReader;
use rawzip::ReaderAt;
use semver::Version;
use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;
use slog::Logger;
use slog::warn;
use tokio::sync::mpsc;
use tufaceous_artifact::Artifact;
use tufaceous_artifact::ArtifactHash;
use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::Artifacts;
use tufaceous_artifact::KnownArtifactTags;
use tufaceous_artifact::OsBoard;
use tufaceous_artifact::OsPhase1Tags;
use tufaceous_artifact::OsPhase2Tags;
use tufaceous_artifact::OsVariant;
use tufaceous_artifact::RotSlot;
use tufaceous_artifact::ZoneTags;
use tufaceous_artifact::hubris::ReadCabooseError;

use crate::COSMO_PHASE_1_PATH;
use crate::GIMLET_PHASE_1_PATH;
use crate::PHASE_2_PATH;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::error::try_path;
use crate::repo::read_target;
use crate::repo::read_target_json;
use crate::repo::read_target_vec;
use crate::repo::sha256_length;

#[derive(Debug, Clone)]
pub(crate) struct Unpacked {
    pub(crate) entries: HashMap<String, UnpackedArtifact>,
}

pub(crate) async fn from_loaded(
    repo: &tough::Repository,
    log: &Logger,
) -> Result<Option<(Version, Artifacts, Unpacked)>, Error> {
    let Some(V1ArtifactsSchema { system_version, artifacts: v1_artifacts }) =
        read_target_json(repo, V1ArtifactsSchema::TARGET_NAME).await?
    else {
        return Ok(None);
    };

    let mut artifacts = Artifacts::default();
    let mut unpacked = Unpacked { entries: HashMap::new() };
    for V1Artifact { version, kind, target } in v1_artifacts {
        let Some((hash, length)) = sha256_length(repo, log, &target) else {
            continue;
        };
        let kind = match kind {
            V1ArtifactKind::Known(kind) => kind,
            V1ArtifactKind::Unknown(kind) => {
                warn!(
                    log,
                    "skipping artifact";
                    "target_name" => &target,
                    "error" => "unknown v1 kind",
                    "kind" => kind,
                );
                continue;
            }
        };
        let tags = match kind {
            V1KnownArtifactKind::GimletSp
            | V1KnownArtifactKind::PscSp
            | V1KnownArtifactKind::SwitchSp => {
                let image = read_target_vec(repo, &target).await?;
                let Some(image) = image else { continue };
                caboose_tags(
                    image,
                    &target,
                    KnownArtifactTags::from_sp_caboose,
                )?
            }
            V1KnownArtifactKind::GimletRotBootloader
            | V1KnownArtifactKind::PscRotBootloader
            | V1KnownArtifactKind::SwitchRotBootloader => {
                let image = read_target_vec(repo, &target).await?;
                let Some(image) = image else { continue };
                caboose_tags(
                    image,
                    &target,
                    KnownArtifactTags::from_rot_bootloader_caboose,
                )?
            }
            V1KnownArtifactKind::GimletRot
            | V1KnownArtifactKind::PscRot
            | V1KnownArtifactKind::SwitchRot => {
                CompositeArtifact::unpack(repo, target)
                    .await?
                    .read_rot(&mut artifacts, &mut unpacked, version)
                    .await?;
                continue;
            }

            V1KnownArtifactKind::Host => {
                CompositeArtifact::unpack(repo, target).await?.read_os_image(
                    &mut artifacts,
                    &mut unpacked,
                    OsVariant::Host,
                    &version,
                );
                continue;
            }
            V1KnownArtifactKind::Trampoline => {
                CompositeArtifact::unpack(repo, target).await?.read_os_image(
                    &mut artifacts,
                    &mut unpacked,
                    OsVariant::Recovery,
                    &version,
                );
                continue;
            }

            V1KnownArtifactKind::InstallinatorDocument => {
                KnownArtifactTags::InstallinatorDocument
            }

            V1KnownArtifactKind::ControlPlane => {
                CompositeArtifact::unpack(repo, target)
                    .await?
                    .read_control_plane(&mut artifacts, &mut unpacked)
                    .await?;
                continue;
            }

            V1KnownArtifactKind::MeasurementCorpus => {
                KnownArtifactTags::MeasurementCorpus
            }
        };

        let target_name = target;
        let tags = tags.to_tags();
        artifacts.insert(Artifact { target_name, version, tags, hash, length });
    }
    Ok(Some((system_version, artifacts, unpacked)))
}

#[derive(Debug, Clone)]
pub(crate) struct UnpackedArtifact {
    file: Arc<FileReader>,
    hash: ArtifactHash,
    length: u64,
}

impl UnpackedArtifact {
    pub(crate) fn stream(
        self,
    ) -> impl Stream<Item = Result<Bytes, Error>> + 'static {
        stream::try_unfold(
            (self, BytesMut::new(), Sha256::new(), 0),
            async |(this, mut buf, mut hasher, mut bytes_read)| {
                if buf.capacity() == 0 {
                    buf.reserve(8192);
                }
                buf.resize(buf.capacity(), 0);
                let (this, mut buf) = tokio::task::spawn_blocking(move || {
                    let n = this.file.read_at(&mut buf, bytes_read).map_err(
                        |source| ErrorKind::ReadFile { source, path: None },
                    )?;
                    buf.truncate(n);
                    Ok::<_, Error>((this, buf))
                })
                .await??;
                let bytes = buf.split().freeze();
                if bytes.is_empty() {
                    let msg = if this.hash
                        != ArtifactHash(hasher.finalize().into())
                    {
                        "invalid checksum"
                    } else if this.length != bytes_read {
                        "invalid length"
                    } else {
                        return Ok(None);
                    };
                    let source = std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        msg,
                    );
                    return Err(
                        ErrorKind::ReadFile { source, path: None }.into()
                    );
                }
                hasher.update(&bytes);
                bytes_read +=
                    u64::try_from(bytes.len()).expect("usize fits in u64");
                Ok(Some((bytes, (this, buf, hasher, bytes_read))))
            },
        )
    }
}

fn caboose_tags(
    image: Vec<u8>,
    target_name: &str,
    f: impl FnOnce(&Caboose) -> Result<KnownArtifactTags, ReadCabooseError>,
) -> Result<KnownArtifactTags, Error> {
    let caboose = try_path!(
        RawHubrisArchive::from_vec(image)
            .and_then(|image| image.read_caboose()),
        ReadHubrisArchive,
        target_name
    );
    Ok(try_path!(f(&caboose), ReadCaboose, target_name))
}

#[derive(Debug)]
struct CompositeArtifact {
    entries: HashMap<Utf8PathBuf, UnpackedArtifact>,
    original_target_name: String,
}

impl CompositeArtifact {
    async fn unpack(
        repo: &tough::Repository,
        target_name: String,
    ) -> Result<Self, Error> {
        let stream =
            read_target(repo, &target_name).await?.ok_or_else(|| {
                ErrorKind::TargetNotFound { target_name: target_name.clone() }
            })?;
        pin_mut!(stream);

        let (tx, rx) = mpsc::channel(1);
        let target_name_clone = target_name.clone();
        let task = tokio::task::spawn_blocking(move || {
            let mut archive =
                tar::Archive::new(GzDecoder::new(MpscReader::new(rx)));
            let mut entries = HashMap::new();
            for entry in archive.entries().map_err(|source| {
                ErrorKind::ReadCompositeArtifact {
                    source,
                    target: target_name.clone(),
                }
            })? {
                let (mut entry, path) = entry
                    .and_then(|entry| {
                        let path = entry.header().path()?.into_owned();
                        let path = Utf8PathBuf::try_from(path)
                            .map_err(FromPathBufError::into_io_error)?;
                        Ok((entry, path))
                    })
                    .map_err(|source| ErrorKind::ReadCompositeArtifact {
                        source,
                        target: target_name.clone(),
                    })?;
                let mut file = camino_tempfile::tempfile()
                    .map_err(ErrorKind::CreateTempFile)?;
                let mut hasher = Sha256::new();
                let mut length = 0u64;
                let mut buf = [0; 8192];
                while let n = entry.read(&mut buf).map_err(|source| {
                    ErrorKind::ReadCompositeArtifact {
                        source,
                        target: target_name.clone(),
                    }
                })? && n > 0
                {
                    file.write_all(&buf[..n]).map_err(|source| {
                        ErrorKind::WriteFile { source, path: None }
                    })?;
                    hasher.update(&buf[..n]);
                    length += u64::try_from(n).expect("usize fits in u64");
                }
                let file = Arc::new(file.into());
                let hash = ArtifactHash(hasher.finalize().into());
                entries.insert(path, UnpackedArtifact { file, hash, length });
            }
            Ok(Self { entries, original_target_name: target_name })
        });

        let mut stream_interrupted = false;
        while let Some(item) = stream.try_next().await? {
            let Ok(()) = tx.send(item).await else {
                // The receiver hung up early. We are not allowed to return `Ok`
                // from this function, otherwise we have not actually verified
                // any of the data we just read against its hash.
                stream_interrupted = true;
                break;
            };
        }
        drop(tx);
        let result = task.await?;
        if stream_interrupted && result.is_ok() {
            // No, it isn't ok.
            Err(ErrorKind::ReadCompositeArtifact {
                source: std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "stream unexpectedly interrupted",
                ),
                target: target_name_clone,
            }
            .into())
        } else {
            result
        }
    }

    async fn read_rot(
        mut self,
        artifacts: &mut Artifacts,
        unpacked: &mut Unpacked,
        version: ArtifactVersion,
    ) -> Result<(), Error> {
        for slot in [RotSlot::A, RotSlot::B] {
            let path = Utf8PathBuf::from(format!("archive-{slot}.zip"));
            let Some(UnpackedArtifact { file, hash, length }) =
                self.entries.remove(&path)
            else {
                continue;
            };

            let mut reader = RangeReader::new(file.clone(), 0..length);
            let image = tokio::task::spawn_blocking(move || {
                let capacity = usize::try_from(length).unwrap_or_default();
                let mut vec = Vec::with_capacity(capacity);
                reader.read_to_end(&mut vec).map(|_| vec).map_err(|source| {
                    ErrorKind::ReadFile { source, path: None }
                })
            })
            .await??;

            let target_name = format!("{}/{path}", self.original_target_name);
            let tags = caboose_tags(image, &target_name, |caboose| {
                KnownArtifactTags::from_rot_caboose(caboose, slot)
            })?;
            artifacts.insert(Artifact {
                target_name: target_name.clone(),
                version: version.clone(),
                tags: tags.to_tags(),
                hash,
                length,
            });
            unpacked
                .entries
                .insert(target_name, UnpackedArtifact { file, hash, length });
        }
        Ok(())
    }

    fn read_os_image(
        mut self,
        artifacts: &mut Artifacts,
        unpacked: &mut Unpacked,
        os_variant: OsVariant,
        version: &ArtifactVersion,
    ) {
        for (file_name, tags) in [
            (
                COSMO_PHASE_1_PATH,
                KnownArtifactTags::OsPhase1(OsPhase1Tags {
                    os_variant,
                    os_board: OsBoard::Cosmo,
                }),
            ),
            (
                GIMLET_PHASE_1_PATH,
                KnownArtifactTags::OsPhase1(OsPhase1Tags {
                    os_variant,
                    os_board: OsBoard::Gimlet,
                }),
            ),
            (
                PHASE_2_PATH,
                KnownArtifactTags::OsPhase2(OsPhase2Tags { os_variant }),
            ),
        ] {
            let path = Utf8PathBuf::from(format!("image/{file_name}"));
            let Some(entry) = self.entries.remove(&path) else {
                continue;
            };
            let target_name = format!("{}/{path}", self.original_target_name);
            artifacts.insert(Artifact {
                target_name: target_name.clone(),
                version: version.clone(),
                tags: tags.to_tags(),
                hash: entry.hash,
                length: entry.length,
            });
            unpacked.entries.insert(target_name, entry);
        }
    }

    async fn read_control_plane(
        self,
        artifacts: &mut Artifacts,
        unpacked: &mut Unpacked,
    ) -> Result<(), Error> {
        for (tar_path, UnpackedArtifact { file, hash, length }) in self.entries
        {
            if !tar_path.starts_with("zones") {
                continue;
            }
            let target_name =
                format!("{}/{tar_path}", self.original_target_name);
            let (file, layer_info) = crate::util::read_zone_layer_info(
                RangeReader::new(file, 0..length),
                target_name.clone().into(),
            )
            .await?;
            let file = file.into_inner();
            artifacts.insert(Artifact {
                target_name: target_name.clone(),
                version: layer_info.version,
                tags: KnownArtifactTags::Zone(ZoneTags {
                    zone_name: layer_info.pkg,
                })
                .to_tags(),
                hash,
                length,
            });
            unpacked
                .entries
                .insert(target_name, UnpackedArtifact { file, hash, length });
        }
        Ok(())
    }
}

struct MpscReader {
    rx: mpsc::Receiver<Bytes>,
    buf: Bytes,
}

impl MpscReader {
    fn new(rx: mpsc::Receiver<Bytes>) -> Self {
        Self { rx, buf: Bytes::new() }
    }
}

impl Read for MpscReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.fill_buf()?;
        let len = self.buf.len().min(buf.len());
        self.buf.copy_to_slice(&mut buf[..len]);
        Ok(len)
    }
}

impl BufRead for MpscReader {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.buf.is_empty()
            && let Some(next) = self.rx.blocking_recv()
        {
            self.buf = next;
        }
        Ok(&self.buf)
    }

    fn consume(&mut self, amount: usize) {
        self.buf.advance(amount);
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct V1ArtifactsSchema {
    system_version: Version,
    artifacts: Vec<V1Artifact>,
}

impl V1ArtifactsSchema {
    pub(crate) const TARGET_NAME: &str = "artifacts.json";
}

#[derive(Debug, Deserialize)]
struct V1Artifact {
    version: ArtifactVersion,
    kind: V1ArtifactKind,
    target: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum V1ArtifactKind {
    Known(V1KnownArtifactKind),
    Unknown(String),
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum V1KnownArtifactKind {
    GimletSp,
    GimletRot,
    GimletRotBootloader,
    Host,
    Trampoline,
    InstallinatorDocument,
    ControlPlane,
    MeasurementCorpus,
    PscSp,
    PscRot,
    PscRotBootloader,
    SwitchSp,
    SwitchRot,
    SwitchRotBootloader,
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use bytes::Bytes;
    use tokio::sync::mpsc;

    use crate::repo::v1::MpscReader;

    #[tokio::test]
    async fn mpsc_reader() {
        static CHUNKS: [Bytes; 5] = [
            Bytes::from_static(b"hello world"),
            Bytes::from_static(&[0x5a; 512]),
            Bytes::from_static(b"meow meow meow meow\0"),
            Bytes::from_static(&[0; 12345]),
            Bytes::from_static(&[0x5a; 256]),
        ];

        let expected = CHUNKS.concat();

        let (tx, rx) = mpsc::channel(1);
        let task = tokio::task::spawn_blocking(move || {
            let mut bytes_read = Vec::new();
            let mut reader = MpscReader::new(rx);
            let mut buf = [0; 2048];
            while let n = reader.read(&mut buf).unwrap()
                && n > 0
            {
                bytes_read.extend_from_slice(&buf[..n]);
            }
            bytes_read
        });
        for chunk in &CHUNKS {
            tx.send(chunk.clone()).await.unwrap();
        }
        drop(tx);
        let bytes_read = task.await.unwrap();
        assert_eq!(bytes_read, expected);
    }

    #[tokio::test]
    async fn mpsc_reader_empty() {
        let (tx, rx) = mpsc::channel(1);
        let task = tokio::task::spawn_blocking(move || {
            let mut bytes_read = Vec::new();
            MpscReader::new(rx).read_to_end(&mut bytes_read).unwrap();
            bytes_read
        });
        drop(tx);
        let bytes_read = task.await.unwrap();
        assert!(bytes_read.is_empty());
    }
}
