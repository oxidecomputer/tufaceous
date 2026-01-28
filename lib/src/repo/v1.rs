// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
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
use flate2::read::GzDecoder;
use futures_util::Stream;
use futures_util::TryStreamExt;
use futures_util::pin_mut;
use futures_util::stream;
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

use crate::COSMO_PHASE_1_PATH;
use crate::GIMLET_PHASE_1_PATH;
use crate::PHASE_2_PATH;
use crate::Repository;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::repo::read_target;
use crate::repo::read_target_json;
use crate::repo::read_target_vec;
use crate::repo::sha256_length;

#[derive(Debug, Clone)]
pub(crate) struct Unpacked {
    pub(crate) entries: HashMap<String, UnpackedArtifact>,
}

pub(crate) async fn from_loaded(
    repo: tough::Repository,
    log: &Logger,
    trust_root: Vec<u8>,
) -> Result<Option<Repository>, Error> {
    let Some(V1ArtifactsSchema { system_version, artifacts: v1_artifacts }) =
        read_target_json(&repo, V1ArtifactsSchema::TARGET_NAME).await?
    else {
        return Ok(None);
    };

    let mut artifacts = Artifacts::default();
    let mut entries = HashMap::new();
    for artifact in v1_artifacts {
        let kind = match artifact.kind {
            V1ArtifactKind::Known(kind) => kind,
            V1ArtifactKind::Unknown(kind) => {
                warn!(
                    log,
                    "skipping artifact";
                    "target_name" => &artifact.target,
                    "error" => "unknown v1 kind",
                    "kind" => kind,
                );
                continue;
            }
        };
        let Some((hash, length)) = sha256_length(&repo, log, &artifact.target)
        else {
            continue;
        };

        match kind {
            V1KnownArtifactKind::GimletSp
            | V1KnownArtifactKind::PscSp
            | V1KnownArtifactKind::SwitchSp => {
                let Some(image) =
                    read_target_vec(&repo, &artifact.target).await?
                else {
                    continue;
                };
                let caboose = RawHubrisArchive::from_vec(image)
                    .and_then(|image| image.read_caboose())
                    .map_err(|source| ErrorKind::ReadHubrisArchive {
                        source,
                        path: artifact.target.clone().into(),
                    })?;
                let tags = KnownArtifactTags::from_sp_caboose(&caboose)
                    .map_err(|source| ErrorKind::ReadCaboose {
                        source,
                        path: artifact.target.clone().into(),
                    })?;
                artifacts.insert(Artifact {
                    target_name: artifact.target,
                    version: artifact.version,
                    tags: tags.to_tags(),
                    hash,
                    length,
                });
            }
            V1KnownArtifactKind::GimletRotBootloader
            | V1KnownArtifactKind::PscRotBootloader
            | V1KnownArtifactKind::SwitchRotBootloader => {
                let Some(image) =
                    read_target_vec(&repo, &artifact.target).await?
                else {
                    continue;
                };
                let caboose = RawHubrisArchive::from_vec(image)
                    .and_then(|image| image.read_caboose())
                    .map_err(|source| ErrorKind::ReadHubrisArchive {
                        source,
                        path: artifact.target.clone().into(),
                    })?;
                let tags =
                    KnownArtifactTags::from_rot_bootloader_caboose(&caboose)
                        .map_err(|source| ErrorKind::ReadCaboose {
                            source,
                            path: artifact.target.clone().into(),
                        })?;
                artifacts.insert(Artifact {
                    target_name: artifact.target,
                    version: artifact.version,
                    tags: tags.to_tags(),
                    hash,
                    length,
                });
            }

            V1KnownArtifactKind::GimletRot
            | V1KnownArtifactKind::PscRot
            | V1KnownArtifactKind::SwitchRot => {
                let target = artifact.target.clone();
                let unpacked =
                    CompositeArtifact::unpack(&repo, &target).await?;
                for (tar_path, inner) in unpacked.entries {
                    let UnpackedArtifact { file, hash, length } = inner;
                    let slot = match tar_path.as_ref() {
                        "archive-a.zip" => RotSlot::A,
                        "archive-b.zip" => RotSlot::B,
                        _ => continue,
                    };
                    let mut reader = RangeReader::new(file.clone(), 0..length);
                    let mut vec = length
                        .try_into()
                        .map(Vec::with_capacity)
                        .unwrap_or_default();
                    let image = tokio::task::spawn_blocking(move || {
                        reader.read_to_end(&mut vec).map(|_| vec).map_err(
                            |source| ErrorKind::ReadFile { source, path: None },
                        )
                    })
                    .await??;
                    let caboose = RawHubrisArchive::from_vec(image)
                        .and_then(|image| image.read_caboose())
                        .map_err(|source| ErrorKind::ReadHubrisArchive {
                            source,
                            path: target.clone().into(),
                        })?;
                    let tags =
                        KnownArtifactTags::from_rot_caboose(&caboose, slot)
                            .map_err(|source| ErrorKind::ReadCaboose {
                                source,
                                path: target.clone().into(),
                            })?;
                    let target_name = format!("{}/{tar_path}", artifact.target);
                    entries.insert(
                        target_name.clone(),
                        UnpackedArtifact { file, hash, length },
                    );
                    artifacts.insert(Artifact {
                        target_name,
                        version: artifact.version.clone(),
                        tags: tags.to_tags(),
                        hash,
                        length,
                    });
                }
            }

            V1KnownArtifactKind::Host => {
                unpack_os(
                    CompositeArtifact::unpack(&repo, &artifact.target).await?,
                    &mut entries,
                    &mut artifacts,
                    &artifact,
                    OsVariant::Host,
                );
            }
            V1KnownArtifactKind::Trampoline => {
                unpack_os(
                    CompositeArtifact::unpack(&repo, &artifact.target).await?,
                    &mut entries,
                    &mut artifacts,
                    &artifact,
                    OsVariant::Recovery,
                );
            }

            V1KnownArtifactKind::InstallinatorDocument => {
                artifacts.insert(Artifact {
                    target_name: artifact.target,
                    version: artifact.version,
                    tags: KnownArtifactTags::InstallinatorDocument {}.to_tags(),
                    hash,
                    length,
                });
            }

            V1KnownArtifactKind::ControlPlane => {
                let unpacked =
                    CompositeArtifact::unpack(&repo, &artifact.target).await?;
                for (tar_path, inner) in unpacked.entries {
                    let UnpackedArtifact { file, hash, length } = inner;
                    if tar_path.starts_with("zones/") {
                        let path = tar_path.to_string();
                        let (file, layer_info) =
                            crate::util::read_zone_layer_info(
                                RangeReader::new(file, 0..length),
                                path.into(),
                            )
                            .await?;
                        let file = file.into_inner();
                        let target_name =
                            format!("{}/{tar_path}", artifact.target);
                        entries.insert(
                            target_name.clone(),
                            UnpackedArtifact { file, hash, length },
                        );
                        artifacts.insert(Artifact {
                            target_name,
                            version: layer_info.version,
                            tags: KnownArtifactTags::Zone(ZoneTags {
                                zone_name: layer_info.pkg,
                            })
                            .to_tags(),
                            hash,
                            length,
                        });
                    }
                }
            }

            V1KnownArtifactKind::MeasurementCorpus => {
                artifacts.insert(Artifact {
                    target_name: artifact.target,
                    version: artifact.version,
                    tags: KnownArtifactTags::MeasurementCorpus {}.to_tags(),
                    hash,
                    length,
                });
            }
        }
    }

    Ok(Some(Repository {
        inner: repo,
        system_version,
        trust_root,
        archive_path: None,
        archive_sha256: None,
        artifacts: Artifacts::new(artifacts),
        metadata: BTreeMap::new(),
        v1_unpacked: Some(Unpacked { entries }),
    }))
}

#[derive(Debug, Clone)]
pub(crate) struct UnpackedArtifact {
    file: Arc<FileReader>,
    hash: ArtifactHash,
    length: u64,
}

impl UnpackedArtifact {
    pub(crate) fn stream(&self) -> impl Stream<Item = Result<Bytes, Error>> {
        stream::try_unfold(
            (BytesMut::new(), Sha256::new(), 0),
            async |(mut buf, mut hasher, mut bytes_read)| {
                if buf.capacity() == 0 {
                    buf.reserve(8192);
                }
                buf.resize(buf.capacity(), 0);
                let file = self.file.clone();
                let mut buf = tokio::task::spawn_blocking(move || {
                    let n = file.read_at(&mut buf, bytes_read).map_err(
                        |source| ErrorKind::ReadFile { source, path: None },
                    )?;
                    buf.truncate(n);
                    Ok::<_, Error>(buf)
                })
                .await??;
                let bytes = buf.split().freeze();
                if bytes.is_empty() {
                    let msg = if self.hash
                        != ArtifactHash(hasher.finalize().into())
                    {
                        "invalid checksum"
                    } else if self.length != bytes_read {
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
                bytes_read += u64::try_from(bytes.len()).unwrap();
                Ok(Some((bytes, (buf, hasher, bytes_read))))
            },
        )
    }
}

#[derive(Debug)]
struct CompositeArtifact {
    entries: HashMap<Utf8PathBuf, UnpackedArtifact>,
}

impl CompositeArtifact {
    async fn unpack(
        repo: &tough::Repository,
        target_name: &str,
    ) -> Result<Self, Error> {
        let stream =
            read_target(repo, target_name).await?.ok_or_else(|| {
                ErrorKind::TargetNotFound {
                    target_name: target_name.to_owned(),
                }
            })?;
        pin_mut!(stream);
        let (tx, rx) = mpsc::channel(1);
        let target_name = target_name.to_owned();
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
                    length += u64::try_from(n).unwrap();
                }
                let file = Arc::new(file.into());
                let hash = ArtifactHash(hasher.finalize().into());
                entries.insert(path, UnpackedArtifact { file, hash, length });
            }
            Ok(Self { entries })
        });
        while let Some(item) = stream.try_next().await? {
            let Ok(()) = tx.send(item).await else { break };
        }
        task.await?
    }
}

fn unpack_os(
    unpacked: CompositeArtifact,
    entries: &mut HashMap<String, UnpackedArtifact>,
    artifacts: &mut Artifacts,
    artifact: &V1Artifact,
    os_variant: OsVariant,
) {
    for (tar_path, inner) in unpacked.entries {
        let tags = match tar_path.as_str().strip_prefix("image/") {
            Some(COSMO_PHASE_1_PATH) => {
                KnownArtifactTags::OsPhase1(OsPhase1Tags {
                    os_variant,
                    os_board: OsBoard::Cosmo,
                })
            }
            Some(GIMLET_PHASE_1_PATH) => {
                KnownArtifactTags::OsPhase1(OsPhase1Tags {
                    os_variant,
                    os_board: OsBoard::Gimlet,
                })
            }
            Some(PHASE_2_PATH) => {
                KnownArtifactTags::OsPhase2(OsPhase2Tags { os_variant })
            }
            _ => continue,
        };
        let target_name = format!("{}/{tar_path}", artifact.target);
        artifacts.insert(Artifact {
            target_name: target_name.clone(),
            version: artifact.version.clone(),
            tags: tags.to_tags(),
            hash: inner.hash,
            length: inner.length,
        });
        entries.insert(target_name, inner);
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
        self.buf.split_to(len).copy_to_slice(buf);
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
