// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;

use bytes::Buf;
use bytes::Bytes;
use bytes::BytesMut;
use camino::FromPathBufError;
use camino::Utf8Path;
use camino::Utf8PathBuf;
use flate2::bufread::GzDecoder;
use futures_util::Stream;
use futures_util::TryStreamExt;
use futures_util::pin_mut;
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
use slog::info;
use slog::o;
use slog::warn;
use tokio::sync::mpsc;
use tufaceous_artifact::Artifact;
use tufaceous_artifact::ArtifactHash;
use tufaceous_artifact::ArtifactSet;
use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::InstallinatorDocument;
use tufaceous_artifact::KnownArtifactTags;
use tufaceous_artifact::OsBoard;
use tufaceous_artifact::OsPhase1Tags;
use tufaceous_artifact::OsPhase2Tags;
use tufaceous_artifact::OsVariant;
use tufaceous_artifact::ReadCabooseError;
use tufaceous_artifact::RotSlot;
use tufaceous_artifact::ZoneTags;

use crate::COSMO_PHASE_1_PATH;
use crate::GIMLET_PHASE_1_PATH;
use crate::PHASE_2_PATH;
use crate::error::DebugByteString;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::error::try_path;
use crate::repo::ArtifactData;
use crate::repo::read_target;
use crate::repo::read_target_json;
use crate::repo::read_target_vec;
use crate::repo::target_meta;
use crate::util::ArtifactExt;

pub(super) struct PartialRepository {
    pub(super) system_version: Version,
    pub(super) artifacts: ArtifactSet,
    pub(super) artifact_data: BTreeMap<Artifact, ArtifactData>,
}

impl PartialRepository {
    fn insert(&mut self, artifact: Artifact, data: ArtifactData) {
        self.artifacts.insert(artifact.clone());
        self.artifact_data.insert(artifact, data);
    }

    fn original_target_name(&self, artifact: &Artifact) -> Option<&str> {
        self.artifact_data.get(artifact).map(ArtifactData::original_target_name)
    }
}

/// Attempt to load a `tough::Repository` as if it is a Tufaceous v1 repository,
/// converting artifacts into the v2 memory representation.
///
/// Returns `None` if the v1 `artifacts.json` wasn't found.
#[expect(clippy::too_many_lines)]
pub(crate) async fn from_loaded(
    tuf_repo: &tough::Repository,
    log: &Logger,
) -> Result<Option<PartialRepository>, Error> {
    let Some(V1ArtifactSetSchema { system_version, artifacts: v1_artifacts }) =
        read_target_json(tuf_repo, V1ArtifactSetSchema::TARGET_NAME).await?
    else {
        return Ok(None);
    };

    let mut partial = PartialRepository {
        system_version,
        artifacts: ArtifactSet::default(),
        artifact_data: BTreeMap::new(),
    };
    let mut installinator_document = None;
    for V1Artifact { version, kind, target } in v1_artifacts {
        let (hash, length) = target_meta(tuf_repo, &target)?;
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
            // These arms represent a single artifact, and return their tags
            // from the match arm.
            V1KnownArtifactKind::GimletSp
            | V1KnownArtifactKind::PscSp
            | V1KnownArtifactKind::SwitchSp => {
                let image = read_target_vec(tuf_repo, &target).await?;
                let Some(image) = image else { continue };
                let mut is_lab_image = false;
                let tags = caboose_tags(image, &target, |caboose| {
                    if let Ok(board) = caboose.board()
                        && let Ok(name) = caboose.name()
                        && board != name
                    {
                        // This is a lab image. These are stored in the TUF repo
                        // for manufacturing but are not used in the control
                        // plane, as they can never be used in an actual rack.
                        info!(
                            log,
                            "skipping lab SP image";
                            "board" => ?DebugByteString(board),
                            "name" => ?DebugByteString(name),
                        );
                        is_lab_image = true;
                    }
                    KnownArtifactTags::from_sp_caboose(caboose)
                })?;
                if is_lab_image {
                    continue;
                }
                tags
            }
            V1KnownArtifactKind::GimletRotBootloader
            | V1KnownArtifactKind::PscRotBootloader
            | V1KnownArtifactKind::SwitchRotBootloader => {
                let image = read_target_vec(tuf_repo, &target).await?;
                let Some(image) = image else { continue };
                let tags = caboose_tags(
                    image,
                    &target,
                    KnownArtifactTags::from_rot_bootloader_caboose,
                )?;
                if partial.artifacts.get_all(&tags).iter().any(|artifact| {
                    if hash == artifact.hash && length == artifact.length {
                        let existing = partial
                            .original_target_name(artifact)
                            .unwrap_or("???");
                        info!(
                            log,
                            "skipping duplicate RoT bootloader image";
                            "existing" => &existing,
                            "skipped" => &target,
                        );
                        true
                    } else {
                        false
                    }
                }) {
                    continue;
                }
                tags
            }

            V1KnownArtifactKind::MeasurementCorpus => {
                KnownArtifactTags::MeasurementCorpus
            }

            // These arms represent composite artifacts, and all diverge
            // with `continue`. They use methods on `CompositeArtifact` to
            // unpack and add multiple artifacts to `partial` instead of the
            // single-artifact logic at the end of this match statement.
            V1KnownArtifactKind::GimletRot
            | V1KnownArtifactKind::PscRot
            | V1KnownArtifactKind::SwitchRot => {
                CompositeArtifact::unpack(tuf_repo, target)
                    .await?
                    .read_rot(log, &mut partial, version)
                    .await?;
                continue;
            }

            V1KnownArtifactKind::Host => {
                CompositeArtifact::unpack(tuf_repo, target)
                    .await?
                    .read_os_image(&mut partial, OsVariant::Host, &version)?;
                continue;
            }
            V1KnownArtifactKind::Trampoline => {
                CompositeArtifact::unpack(tuf_repo, target)
                    .await?
                    .read_os_image(
                        &mut partial,
                        OsVariant::Recovery,
                        &version,
                    )?;
                continue;
            }

            V1KnownArtifactKind::ControlPlane => {
                CompositeArtifact::unpack(tuf_repo, target)
                    .await?
                    .read_control_plane(&mut partial)
                    .await?;
                continue;
            }

            // Do not directly use any Installinator document, because it is
            // written for the v1 artifacts. We need to generate a new one
            // for the v2 artifacts once all of the potential artifacts are
            // extracted.
            V1KnownArtifactKind::InstallinatorDocument => {
                installinator_document = Some((version, target));
                continue;
            }
        };

        let tags = tags.to_tags().map_err(ErrorKind::ConvertKnownTagsToMap)?;
        partial.insert(
            Artifact { version, tags, hash, length },
            ArtifactData::Target { target_name: target },
        );
    }

    // If we found an Installinator document, generate a new one with the v2
    // artifacts.
    if let Some((version, target)) = installinator_document {
        generate_installinator_document(&mut partial, version, target).await?;
    }
    Ok(Some(partial))
}

#[derive(Debug, Clone)]
pub(super) struct UnpackedArtifact {
    pub(super) file: Arc<FileReader>,
    pub(super) hash: ArtifactHash,
    pub(super) length: u64,
}

impl UnpackedArtifact {
    fn new_blocking(
        reader: &mut dyn BufRead,
        map_read_err: impl FnOnce(std::io::Error) -> ErrorKind,
    ) -> Result<Self, Error> {
        let mut file =
            camino_tempfile::tempfile().map_err(ErrorKind::CreateTempFile)?;
        let mut hasher = Sha256::new();
        let mut length = 0u64;
        loop {
            let buf = match reader.fill_buf() {
                Ok(buf) => buf,
                Err(error) => return Err(map_read_err(error).into()),
            };
            if buf.is_empty() {
                break;
            }
            let len = buf.len();
            file.write_all(buf).map_err(|source| ErrorKind::WriteFile {
                source,
                path: None,
            })?;
            hasher.update(buf);
            reader.consume(len);
            length += usize64!(len);
        }
        let file = Arc::new(file.into());
        let hash = ArtifactHash(hasher.finalize().0);
        Ok(Self { file, hash, length })
    }

    pub(crate) fn stream(
        self,
        log: &Logger,
        original_target_name: &str,
        inner_path: &Utf8Path,
    ) -> impl Stream<Item = Result<Bytes, Error>> + 'static {
        let log = log.new(o!(
            "stream" => format!("{}::stream", std::any::type_name::<Self>()),
            "original_target_name" => original_target_name.to_owned(),
            "inner_path" => inner_path.to_string(),
        ));
        crate::mpsc_stream::mpsc_stream(Some(log), move |tx| {
            type SendError = mpsc::error::SendError<Result<Bytes, Error>>;

            let mut buf = BytesMut::with_capacity(8192);
            let mut hasher = Sha256::new();
            let mut bytes_read = 0;
            loop {
                if buf.capacity() == 0 {
                    buf.reserve(8192);
                }
                buf.resize(buf.capacity(), 0);
                match self.file.read_at(&mut buf, bytes_read) {
                    Ok(n) => {
                        buf.truncate(n);
                    }
                    Err(source) => {
                        let err = ErrorKind::ReadFile { source, path: None };
                        return tx.blocking_send(Err(err.into()));
                    }
                }

                let bytes = buf.split().freeze();
                if bytes.is_empty() {
                    break;
                }
                hasher.update(&bytes);
                bytes_read += usize64!(bytes.len());
                tx.blocking_send(Ok(bytes))?;
            }

            let msg = if self.hash != ArtifactHash(hasher.finalize().into()) {
                "invalid checksum"
            } else if self.length != bytes_read {
                "invalid length"
            } else {
                // correct checksum and length
                return Ok::<_, SendError>(());
            };
            let source =
                std::io::Error::new(std::io::ErrorKind::InvalidData, msg);
            tx.blocking_send(Err(
                ErrorKind::ReadFile { source, path: None }.into()
            ))
        })
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
        tuf_repo: &tough::Repository,
        target_name: String,
    ) -> Result<Self, Error> {
        let stream =
            read_target(tuf_repo, &target_name).await?.ok_or_else(|| {
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
                let (entry, path) = entry
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
                let mut entry = BufReader::new(entry);
                let unpacked_artifact =
                    UnpackedArtifact::new_blocking(&mut entry, |source| {
                        ErrorKind::ReadCompositeArtifact {
                            source,
                            target: target_name.clone(),
                        }
                    })?;
                entries.insert(path, unpacked_artifact);
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
        log: &Logger,
        partial: &mut PartialRepository,
        version: ArtifactVersion,
    ) -> Result<(), Error> {
        for slot in [RotSlot::A, RotSlot::B] {
            let path = Utf8PathBuf::from(match slot {
                RotSlot::A => "archive-a.zip",
                RotSlot::B => "archive-b.zip",
            });
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
                    Error::from(ErrorKind::ReadFile { source, path: None })
                })
            })
            .await??;

            let tags = caboose_tags(
                image,
                &format!("{}/{path}", self.original_target_name),
                |caboose| KnownArtifactTags::from_rot_caboose(caboose, slot),
            )?;
            if partial.artifacts.get_all(&tags).iter().any(|artifact| {
                if hash == artifact.hash && length == artifact.length {
                    let existing =
                        partial.original_target_name(artifact).unwrap_or("???");
                    info!(
                        log,
                        "skipping duplicate RoT image";
                        "existing_target" => &existing,
                        "skipped_target" => &self.original_target_name,
                        "skipped_inner_file" => &path.as_str(),
                    );
                    true
                } else {
                    false
                }
            }) {
                continue;
            }
            partial.insert(
                Artifact {
                    version: version.clone(),
                    tags: tags
                        .to_tags()
                        .map_err(ErrorKind::ConvertKnownTagsToMap)?,
                    hash,
                    length,
                },
                ArtifactData::V1Unpacked {
                    file,
                    original_target_name: self.original_target_name.clone(),
                    inner_path: path,
                },
            );
        }
        Ok(())
    }

    fn read_os_image(
        mut self,
        partial: &mut PartialRepository,
        os_variant: OsVariant,
        version: &ArtifactVersion,
    ) -> Result<(), Error> {
        for (file_name, tags) in [
            (
                COSMO_PHASE_1_PATH,
                KnownArtifactTags::OsPhase1(OsPhase1Tags {
                    os_variant,
                    os_board: OsBoard::COSMO,
                }),
            ),
            (
                GIMLET_PHASE_1_PATH,
                KnownArtifactTags::OsPhase1(OsPhase1Tags {
                    os_variant,
                    os_board: OsBoard::GIMLET,
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
            partial.insert(
                Artifact {
                    version: version.clone(),
                    tags: tags
                        .to_tags()
                        .map_err(ErrorKind::ConvertKnownTagsToMap)?,
                    hash: entry.hash,
                    length: entry.length,
                },
                ArtifactData::V1Unpacked {
                    file: entry.file,
                    original_target_name: self.original_target_name.clone(),
                    inner_path: path,
                },
            );
        }
        Ok(())
    }

    async fn read_control_plane(
        self,
        partial: &mut PartialRepository,
    ) -> Result<(), Error> {
        for (tar_path, UnpackedArtifact { file, hash, length }) in self.entries
        {
            if !tar_path.starts_with("zones/") {
                continue;
            }
            let (file, layer_info) = crate::util::read_zone_layer_info(
                RangeReader::new(file, 0..length),
                Utf8Path::new(&self.original_target_name).join(&tar_path),
            )
            .await?;
            let file = file.into_inner();
            let tags =
                KnownArtifactTags::Zone(ZoneTags { zone_name: layer_info.pkg });
            partial.insert(
                Artifact {
                    version: layer_info.version,
                    tags: tags
                        .to_tags()
                        .map_err(ErrorKind::ConvertKnownTagsToMap)?,
                    hash,
                    length,
                },
                ArtifactData::V1Unpacked {
                    file,
                    original_target_name: self.original_target_name.clone(),
                    inner_path: tar_path,
                },
            );
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

async fn generate_installinator_document(
    partial: &mut PartialRepository,
    version: ArtifactVersion,
    original_target_name: String,
) -> Result<(), Error> {
    let mut document = InstallinatorDocument::empty(version.clone());
    for (artifact, data) in &partial.artifact_data {
        let target_name = match data {
            ArtifactData::Target { target_name } => target_name,
            ArtifactData::V1Unpacked { inner_path, .. } => inner_path.as_str(),
        };
        if let Some(installinator) = artifact.to_installinator(target_name) {
            document.artifacts.insert(installinator);
        }
    }

    let mut json = serde_json::to_string_pretty(&document)
        .map_err(ErrorKind::SerializeInstallinator)?;
    json.push('\n');
    let unpacked_artifact = tokio::task::spawn_blocking(move || {
        UnpackedArtifact::new_blocking(&mut json.as_bytes(), |_error| {
            unreachable!("Read::read for &[u8] does not return an error")
        })
    })
    .await??;

    partial.insert(
        Artifact {
            version,
            tags: KnownArtifactTags::InstallinatorDocument
                .to_tags()
                .map_err(ErrorKind::ConvertKnownTagsToMap)?,
            hash: unpacked_artifact.hash,
            length: unpacked_artifact.length,
        },
        ArtifactData::V1Unpacked {
            file: unpacked_artifact.file,
            original_target_name,
            inner_path: "v2.json".into(),
        },
    );
    Ok(())
}

#[derive(Debug, Deserialize)]
pub(crate) struct V1ArtifactSetSchema {
    system_version: Version,
    artifacts: Vec<V1Artifact>,
}

impl V1ArtifactSetSchema {
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
