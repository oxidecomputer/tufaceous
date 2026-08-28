// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
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
use tokio::task::JoinSet;
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
use tufaceous_brand_metadata::Metadata;

use crate::COSMO_PHASE_1_PATH;
use crate::GIMLET_PHASE_1_PATH;
use crate::PHASE_2_PATH;
use crate::V1CompatibilityMode;
use crate::error::DebugByteString;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::error::try_path;
use crate::repo::ArtifactData;
use crate::repo::InstallinatorV1Artifact;
use crate::repo::read_target;
use crate::repo::read_target_json;
use crate::repo::read_target_vec;
use crate::repo::target_meta;
use crate::util::ArtifactExt;

macro_rules! read_target {
    ($tuf_repo:expr, $target:expr) => {
        match read_target($tuf_repo, &$target).await? {
            Some(stream) => stream,
            None => {
                return Err(
                    ErrorKind::TargetNotFound { target_name: $target }.into()
                )
            }
        }
    };
}

pub(super) struct PartialRepository {
    pub(super) system_version: Version,
    pub(super) installinator_v1_document: Option<ArtifactHash>,
    pub(super) inner: PartialRepositoryInner,
}

#[derive(Default)]
pub(super) struct PartialRepositoryInner {
    pub(super) artifacts: ArtifactSet,
    pub(super) artifact_data: BTreeMap<Artifact, ArtifactData>,
    pub(super) installinator_v1_artifacts: Vec<InstallinatorV1Artifact>,
}

impl PartialRepositoryInner {
    fn insert(&mut self, artifact: Artifact, data: Option<ArtifactData>) {
        self.artifacts.insert(artifact.clone());
        if let Some(data) = data {
            self.artifact_data.insert(artifact, data);
        }
    }

    fn original_target_name(&self, artifact: &Artifact) -> Option<&str> {
        self.artifact_data.get(artifact).map(ArtifactData::original_target_name)
    }

    fn append(&mut self, other: Self) {
        self.artifacts.extend(other.artifacts);
        self.artifact_data.extend(other.artifact_data);
        self.installinator_v1_artifacts
            .extend(other.installinator_v1_artifacts);
    }
}

/// Attempt to load a `tough::Repository` as if it is a Tufaceous v1 repository,
/// converting artifacts into the v2 memory representation.
///
/// Returns `None` if the v1 `artifacts.json` wasn't found.
#[expect(clippy::too_many_lines)]
pub(crate) async fn from_loaded(
    tuf_repo: &tough::Repository,
    compatibility_mode: V1CompatibilityMode,
    log: &Logger,
) -> Result<Option<PartialRepository>, Error> {
    let Some(V1ArtifactSetSchema { system_version, artifacts: v1_artifacts }) =
        read_target_json(tuf_repo, V1ArtifactSetSchema::TARGET_NAME).await?
    else {
        return Ok(None);
    };

    let mut partial = PartialRepository {
        system_version,
        installinator_v1_document: None,
        inner: PartialRepositoryInner::default(),
    };
    let mut installinator_document = None;
    let mut parallel = JoinSet::<Result<PartialRepositoryInner, Error>>::new();
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
                let artifacts = &partial.inner.artifacts;
                if artifacts.get_all(&tags).iter().any(|artifact| {
                    if hash == artifact.hash && length == artifact.length {
                        let existing = partial
                            .inner
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
                let stream = read_target!(tuf_repo, target);
                partial.inner = read_composite_artifact(
                    partial.inner,
                    CompositeArtifactKind::Rot,
                    stream,
                    target,
                    version,
                    compatibility_mode,
                )
                .await?;
                continue;
            }

            V1KnownArtifactKind::Host => {
                let stream = read_target!(tuf_repo, target);
                parallel.spawn(async move {
                    read_composite_artifact(
                        PartialRepositoryInner::default(),
                        CompositeArtifactKind::Os(OsVariant::Host),
                        stream,
                        target,
                        version,
                        compatibility_mode,
                    )
                    .await
                });
                continue;
            }
            V1KnownArtifactKind::Trampoline => {
                let stream = read_target!(tuf_repo, target);
                parallel.spawn(async move {
                    read_composite_artifact(
                        PartialRepositoryInner::default(),
                        CompositeArtifactKind::Os(OsVariant::Recovery),
                        stream,
                        target,
                        version,
                        compatibility_mode,
                    )
                    .await
                });
                continue;
            }

            V1KnownArtifactKind::ControlPlane => {
                partial.inner.installinator_v1_artifacts.push(
                    InstallinatorV1Artifact {
                        version: version.clone(),
                        hash,
                        length,
                        target_name: target.clone(),
                    },
                );
                let stream = read_target!(tuf_repo, target);
                parallel.spawn(async move {
                    read_composite_artifact(
                        PartialRepositoryInner::default(),
                        CompositeArtifactKind::ControlPlane,
                        stream,
                        target,
                        version,
                        compatibility_mode,
                    )
                    .await
                });
                continue;
            }

            // Do not directly use any Installinator document, because it is
            // written for the v1 artifacts. We need to generate a new one
            // for the v2 artifacts once all of the potential artifacts are
            // extracted.
            V1KnownArtifactKind::InstallinatorDocument => {
                partial.installinator_v1_document = Some(hash);
                partial.inner.installinator_v1_artifacts.push(
                    InstallinatorV1Artifact {
                        version: version.clone(),
                        hash,
                        length,
                        target_name: target.clone(),
                    },
                );
                installinator_document = Some((version, target));
                continue;
            }
        };

        let tags = tags.to_tags().map_err(ErrorKind::ConvertKnownTagsToMap)?;
        partial.inner.insert(
            Artifact { version, tags, hash, length },
            Some(ArtifactData::Target { target_name: target }),
        );
    }

    for result in parallel.join_all().await {
        partial.inner.append(result?);
    }

    // If we found an Installinator document, generate a new one with the v2
    // artifacts.
    if let Some((version, target)) = installinator_document {
        generate_installinator_document(&mut partial, version, target).await?;
    }
    Ok(Some(partial))
}

#[derive(Debug, Clone)]
pub(super) struct Unpacked {
    file: Arc<FileReader>,
    pub(super) original_target_name: String,
    inner_path: Utf8PathBuf,
}

impl Unpacked {
    pub(super) fn stream(
        self,
        log: &Logger,
        artifact: &Artifact,
    ) -> impl Stream<Item = Result<Bytes, Error>> + 'static {
        let log = log.new(o!(
            "stream" => format!("{}::stream", std::any::type_name::<Self>()),
            "original_target_name" => self.original_target_name,
            "inner_path" => self.inner_path.into_string(),
        ));
        let hash = artifact.hash;
        let length = artifact.length;
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

            let msg = if hash != ArtifactHash(hasher.finalize().into()) {
                "invalid checksum"
            } else if length != bytes_read {
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

#[derive(Clone, Copy)]
enum CompositeArtifactKind {
    ControlPlane,
    Os(OsVariant),
    Rot,
}

async fn read_composite_artifact(
    partial: PartialRepositoryInner,
    kind: CompositeArtifactKind,
    stream: impl Stream<Item = Result<Bytes, Error>>,
    target_name: String,
    version: ArtifactVersion,
    compatibility_mode: V1CompatibilityMode,
) -> Result<PartialRepositoryInner, Error> {
    if !compatibility_mode.should_read_composite() {
        return Ok(partial);
    }
    pin_mut!(stream);
    let (tx, rx) = mpsc::channel(1);
    let target_name_clone = target_name.clone();
    let map_read_err = move |source| {
        Error::from(ErrorKind::ReadCompositeArtifact {
            source,
            target: target_name_clone.clone(),
        })
    };
    let map_read_err_clone = map_read_err.clone();
    let task = tokio::task::spawn_blocking(move || {
        read_composite_artifact_inner(
            partial,
            kind,
            &target_name,
            &version,
            compatibility_mode,
            MpscReader::new(rx),
            &map_read_err,
        )
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
        Err(map_read_err_clone(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "stream unexpectedly interrupted",
        )))
    } else {
        result
    }
}

fn read_composite_artifact_inner(
    mut partial: PartialRepositoryInner,
    kind: CompositeArtifactKind,
    target_name: &str,
    version: &ArtifactVersion,
    compatibility_mode: V1CompatibilityMode,
    reader: MpscReader,
    map_read_err: &dyn Fn(std::io::Error) -> Error,
) -> Result<PartialRepositoryInner, Error> {
    let mut archive = tar::Archive::new(GzDecoder::new(reader));
    for entry in archive.entries().map_err(&map_read_err)? {
        let (mut entry, path) = entry
            .and_then(|entry| {
                let path = entry.header().path()?.into_owned();
                let path = Utf8PathBuf::try_from(path)
                    .map_err(FromPathBufError::into_io_error)?;
                Ok((entry, path))
            })
            .map_err(&map_read_err)?;
        let virtual_path = Utf8Path::new(&target_name).join(&path);
        let (tags, version, hash, length, file) = match kind {
            CompositeArtifactKind::ControlPlane => {
                if !path.starts_with("zones/") {
                    continue;
                }
                let reader = BufReader::new(ReplayReader::new(entry));
                let mut archive = tar::Archive::new(GzDecoder::new(reader));
                let layer_info = try_path!(
                    Metadata::read_from_tar(&mut archive)
                        .and_then(Metadata::into_layer_info),
                    ReadZoneOxideJson,
                    path
                );
                let tags =
                    ZoneTags { zone_name: layer_info.pkg.clone() }.into();
                let mut file = MaybeTempFile::new(compatibility_mode)?;
                let mut reader = archive
                    .into_inner()
                    .into_inner()
                    .into_inner()
                    .start_replay();
                let (hash, length) =
                    copy_and_hash(&mut reader, &mut file, &map_read_err)?;
                (tags, layer_info.version.clone(), hash, length, file)
            }
            CompositeArtifactKind::Os(os_variant) => {
                let Ok(path) = path.strip_prefix("image") else {
                    continue;
                };
                let tags: KnownArtifactTags = match path.as_str() {
                    COSMO_PHASE_1_PATH => {
                        OsPhase1Tags { os_board: OsBoard::COSMO, os_variant }
                            .into()
                    }
                    GIMLET_PHASE_1_PATH => {
                        OsPhase1Tags { os_board: OsBoard::GIMLET, os_variant }
                            .into()
                    }
                    PHASE_2_PATH => OsPhase2Tags { os_variant }.into(),
                    _ => continue,
                };
                let mut file = MaybeTempFile::new(compatibility_mode)?;
                let (hash, length) =
                    copy_and_hash(&mut entry, &mut file, &map_read_err)?;
                (tags, version.clone(), hash, length, file)
            }
            CompositeArtifactKind::Rot => {
                let slot = match path.as_str() {
                    "archive-a.zip" => RotSlot::A,
                    "archive-b.zip" => RotSlot::B,
                    _ => continue,
                };
                // Regardless of `compatibility_mode` (which can either be
                // `HashCompositeArtifacts` or `ExtractCompositeArtifacts`),
                // we need to read the artifact into memory in order to read
                // tags from the caboose.
                let length_hint = entry.size().try_into().unwrap_or_default();
                let mut image = Vec::with_capacity(length_hint);
                let (hash, length) =
                    copy_and_hash(&mut entry, &mut image, &map_read_err)?;
                let mut file = MaybeTempFile::new(compatibility_mode)?;
                try_path!(file.write_all(&image), WriteFile, None);
                let tags =
                    caboose_tags(image, virtual_path.as_str(), |caboose| {
                        KnownArtifactTags::from_rot_caboose(caboose, slot)
                    })?;
                (tags, version.clone(), hash, length, file)
            }
        };
        let artifact = Artifact {
            version,
            tags: tags.to_tags().map_err(ErrorKind::ConvertKnownTagsToMap)?,
            hash,
            length,
        };
        let data = file.0.map(|file| {
            ArtifactData::V1Unpacked(Unpacked {
                file: Arc::new(file.into()),
                original_target_name: target_name.to_owned(),
                inner_path: path,
            })
        });
        partial.insert(artifact, data);
    }
    Ok(partial)
}

fn copy_and_hash(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    map_read_err: &dyn Fn(std::io::Error) -> Error,
) -> Result<(ArtifactHash, u64), Error> {
    let mut hasher = Sha256::new();
    let mut length = 0u64;
    let mut buf = [0; 8192];
    loop {
        let n = reader.read(&mut buf).map_err(map_read_err)?;
        let slice = &buf[..n];
        if slice.is_empty() {
            break;
        }
        try_path!(writer.write_all(slice), WriteFile, None);
        hasher.update(slice);
        length += usize64!(n);
    }
    Ok((ArtifactHash(hasher.finalize().0), length))
}

struct MaybeTempFile(Option<std::fs::File>);

impl MaybeTempFile {
    fn new(compatibility_mode: V1CompatibilityMode) -> Result<Self, Error> {
        if compatibility_mode.should_extract_composite() {
            let file = camino_tempfile::tempfile()
                .map_err(ErrorKind::CreateTempFile)?;
            Ok(Self(Some(file)))
        } else {
            Ok(Self(None))
        }
    }
}

impl Write for MaybeTempFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.0 {
            Some(file) => file.write(buf),
            None => Ok(buf.len()),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match &mut self.0 {
            Some(file) => file.write_all(buf),
            None => Ok(()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.0 {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

enum ReplayReader<R: Read> {
    Record { record: BytesMut, inner: R },
    Replay { recorded: Bytes, inner: R },
}

impl<R: Read> ReplayReader<R> {
    fn new(inner: R) -> Self {
        Self::Record { record: BytesMut::new(), inner }
    }

    fn start_replay(self) -> Self {
        match self {
            Self::Record { record, inner } => {
                Self::Replay { recorded: record.freeze(), inner }
            }
            Self::Replay { .. } => self,
        }
    }
}

impl<R: Read> Read for ReplayReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            ReplayReader::Record { record, inner } => {
                let n = inner.read(buf)?;
                record.extend_from_slice(&buf[..n]);
                Ok(n)
            }
            ReplayReader::Replay { recorded, inner } => {
                if recorded.is_empty() {
                    inner.read(buf)
                } else {
                    let n = recorded.len().min(buf.len());
                    recorded.copy_to_slice(&mut buf[..n]);
                    Ok(n)
                }
            }
        }
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
    for (artifact, data) in &partial.inner.artifact_data {
        let target_name = match data {
            ArtifactData::Target { target_name } => target_name,
            ArtifactData::V1Unpacked(unpacked) => unpacked.inner_path.as_str(),
        };
        if let Some(installinator) = artifact.to_installinator(target_name) {
            document.artifacts.insert(installinator);
        }
    }

    let mut json = serde_json::to_string_pretty(&document)
        .map_err(ErrorKind::SerializeInstallinator)?;
    json.push('\n');
    let mut file =
        camino_tempfile::tempfile().map_err(ErrorKind::CreateTempFile)?;
    let (file, hash, length) = tokio::task::spawn_blocking(move || {
        let (hash, length) =
            copy_and_hash(&mut json.as_bytes(), &mut file, &|_source| {
                unreachable!("Read::read for &[u8] does not return an error")
            })?;
        Ok::<_, Error>((file, hash, length))
    })
    .await??;

    partial.inner.insert(
        Artifact {
            version,
            tags: KnownArtifactTags::InstallinatorDocument
                .to_tags()
                .map_err(ErrorKind::ConvertKnownTagsToMap)?,
            hash,
            length,
        },
        Some(ArtifactData::V1Unpacked(Unpacked {
            file: Arc::new(file.into()),
            original_target_name,
            inner_path: "v2.json".into(),
        })),
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
