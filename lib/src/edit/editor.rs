// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Read;

use camino::Utf8Path;
use camino::Utf8PathBuf;
use flate2::read::GzDecoder;
use futures_util::FutureExt;
use futures_util::TryFutureExt;
use hubtools::Caboose;
use rats_corim::Corim;
use semver::Version;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::task::JoinSet;
use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::InstallinatorArtifact;
use tufaceous_artifact::InstallinatorDocument;
use tufaceous_artifact::KnownArtifactTags;
use tufaceous_artifact::OsBoard;
use tufaceous_artifact::OsVariant;
use tufaceous_artifact::RotSlot;
use tufaceous_artifact::Sign;
use tufaceous_artifact::hubris::ReadCabooseError;
use tufaceous_brand_metadata::LayerInfo;
use tufaceous_brand_metadata::Metadata;

use crate::Repository;
use crate::edit::UnsignedRepository;
use crate::edit::source::BytesSource;
use crate::edit::source::FakeSource;
use crate::edit::source::FileSource;
use crate::edit::source::RepositorySource;
use crate::edit::source::Target;
use crate::edit::source::TargetSource;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::error::try_path;
use crate::schema::ArtifactSchema;
use crate::schema::ArtifactsSchema;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

#[derive(Debug)]
pub struct RepositoryEditor<'a> {
    system_version: Version,
    generate_installinator_document: bool,
    targets: HashMap<String, Vec<TargetSource<'a>>>,
    artifacts: HashMap<String, HashSet<ArtifactSchema>>,
    metadata: BTreeMap<String, serde_json::Value>,
}

impl<'a> RepositoryEditor<'a> {
    /// Create an empty repository editor.
    pub fn new(system_version: Version) -> Self {
        Self {
            system_version,
            generate_installinator_document: true,
            targets: HashMap::new(),
            artifacts: HashMap::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Change the system version of the repository.
    pub fn system_version(self, system_version: Version) -> Self {
        Self { system_version, ..self }
    }

    /// Sets whether an Installinator document should be generated based on the
    /// artifacts in the repository.
    ///
    /// Defaults to `true`. The document is generated during
    /// [`RepositoryEditor::finish`].
    pub fn generate_installinator_document(
        self,
        generate_installinator_document: bool,
    ) -> Self {
        Self { generate_installinator_document, ..self }
    }

    /// Add a measurement corpus to the repository.
    pub async fn measurement_corpus(
        self,
        path: Utf8PathBuf,
    ) -> Result<Self, Error> {
        self.measurement_corpus_inner(FileSource::open(path).await?, None).await
    }

    async fn measurement_corpus_inner(
        mut self,
        mut source: FileSource,
        corim: Option<Corim>,
    ) -> Result<Self, Error> {
        let Corim { id, .. } = match corim {
            Some(corim) => corim,
            None => {
                let vec = source.read_to_end().await?;
                try_path!(
                    ciborium::from_reader(vec.as_slice()),
                    Corim,
                    source.path
                )
            }
        };
        let sha256 = source.sha256().await?;
        let target_name =
            format!("measurements/{id}-{}.cbor", hex::encode(sha256));
        let version = ArtifactVersion::new(self.system_version.to_string())?;
        let tags = KnownArtifactTags::MeasurementCorpus {};
        self.insert_artifact(target_name, version, tags, source);
        Ok(self)
    }

    fn guess_measurement_corpus(
        mut file_start: &[u8],
    ) -> (bool, Option<Corim>) {
        if !matches!(file_start[0], 0xa0..=0xbf /* CBOR map */) {
            return (false, None);
        }
        match ciborium::from_reader::<Corim, _>(&mut file_start) {
            Ok(corim) => (true, Some(corim)),
            Err(ciborium::de::Error::Io(err))
                if err.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                // This was plausibly a CoRIM manifest until we hit the end of
                // the buffer, indicating a very high likelihood that if we read
                // the entire thing it'd still be a CoRIM manifest.
                (true, None)
            }
            Err(_) => (false, None),
        }
    }

    /// Add an OS image to the repository.
    ///
    /// `output_dir` is a path to the output directory for `helios-build image`
    /// (the `-o` argument). This directory contains `cosmo.rom`, `gimlet.rom`,
    /// `zfs.img`, and `os.tar.gz`. Metadata stored in `os.tar.gz` is copied
    /// into the repository.
    pub async fn os_image_dir(
        mut self,
        variant: OsVariant,
        output_dir: &Utf8Path,
    ) -> Result<Self, Error> {
        let base = Utf8PathBuf::from(format!("os-{variant}"));
        let version = ArtifactVersion::new(self.system_version.to_string())?;

        self.insert_artifact(
            base.join("image/cosmo.rom").into(),
            version.clone(),
            KnownArtifactTags::OsPhase1 { variant, board: OsBoard::Cosmo },
            FileSource::open(output_dir.join("cosmo.rom")).await?,
        );
        self.insert_artifact(
            base.join("image/gimlet.rom").into(),
            version.clone(),
            KnownArtifactTags::OsPhase1 { variant, board: OsBoard::Gimlet },
            FileSource::open(output_dir.join("gimlet.rom")).await?,
        );
        self.insert_artifact(
            base.join("image/zfs.img").into(),
            version,
            KnownArtifactTags::OsPhase2 { variant },
            FileSource::open(output_dir.join("zfs.img")).await?,
        );
        for path in ["cpio.z", "unix.z"] {
            let source = FileSource::open(output_dir.join(path)).await?;
            self.targets
                .entry(base.join("image").join(path).into())
                .or_default()
                .push(TargetSource::File(source));
        }

        let tarball_path = output_dir.join("os.tar.gz");
        let metadata_sources = tokio::task::spawn_blocking(move || {
            let mut sources = Vec::new();
            let file = try_path!(
                std::fs::File::open(&tarball_path),
                OpenFile,
                tarball_path
            );
            let mut archive = tar::Archive::new(GzDecoder::new(file));
            for entry in try_path!(archive.entries(), ReadFile, tarball_path) {
                let mut entry = try_path!(entry, ReadFile, tarball_path);
                if entry.header().entry_type() != tar::EntryType::Regular {
                    continue;
                }
                let path = try_path!(
                    entry.path().and_then(|path| {
                        Utf8PathBuf::try_from(path.into_owned())
                            .map_err(|error| error.into_io_error())
                    }),
                    ReadFile,
                    tarball_path
                );
                if path == "image/zfs.img" {
                    break;
                }
                let mut vec = Vec::new();
                try_path!(entry.read_to_end(&mut vec), ReadFile, tarball_path);
                sources.push((path, vec));
            }
            Ok::<_, Error>(sources)
        })
        .await??;
        for (path, source) in metadata_sources {
            self.targets
                .entry(base.join(path).into())
                .or_default()
                .push(TargetSource::Bytes(BytesSource(source.into())));
        }

        Ok(self)
    }

    async fn guess_os_image(path: &Utf8Path) -> Option<OsVariant> {
        if !path.join("os.tar.gz").exists() {
            return None;
        }
        let mut file = File::open(path.join("zfs.img")).await.ok()?;
        // Read the header block from the image and guess whether it's a
        // recovery image based on the image name.
        let mut buf = [0; 4096];
        file.read_exact(&mut buf).await.ok()?;
        if !buf.starts_with(&0x1DEB0075_u32.to_le_bytes()) {
            return None;
        }
        // see https://github.com/oxidecomputer/boot-image-tools/blob/main/src/diskimage.rs
        let image_name = &buf[200..328];
        Some(if image_name.starts_with(b"recovery") {
            OsVariant::Recovery
        } else {
            OsVariant::Host
        })
    }

    pub async fn rot_archive(
        self,
        slot: RotSlot,
        path: Utf8PathBuf,
    ) -> Result<Self, Error> {
        self.hubris_archive(path, |caboose| {
            KnownArtifactTags::from_rot_caboose(caboose, slot)
        })
        .await
    }

    pub async fn rot_bootloader_archive(
        self,
        path: Utf8PathBuf,
    ) -> Result<Self, Error> {
        self.hubris_archive(
            path,
            KnownArtifactTags::from_rot_bootloader_caboose,
        )
        .await
    }

    pub async fn sp_archive(self, path: Utf8PathBuf) -> Result<Self, Error> {
        self.hubris_archive(path, KnownArtifactTags::from_sp_caboose).await
    }

    async fn hubris_archive<F>(
        self,
        path: Utf8PathBuf,
        tag_fn: F,
    ) -> Result<Self, Error>
    where
        F: FnOnce(&Caboose) -> Result<KnownArtifactTags, ReadCabooseError>,
    {
        let mut source = FileSource::open(path.clone()).await?;
        let caboose = source.read_hubris_caboose().await?;
        let data = CabooseData::new(&caboose, tag_fn, &path)?;
        Ok(self.hubris_archive_inner(source, data))
    }

    fn hubris_archive_inner(
        mut self,
        source: FileSource,
        CabooseData { tags, name, version }: CabooseData,
    ) -> Self {
        let target_name = match &tags {
            KnownArtifactTags::Rot { board, sign, slot } => {
                format!("rot/{board}-{sign}-{version}-slot-{slot}.zip")
            }
            KnownArtifactTags::RotBootloader { board, sign } => {
                format!("rot-bootloader/{board}-{sign}-{version}.zip")
            }
            KnownArtifactTags::Sp { board } => {
                let target_name = format!("sp/{name}-{version}.zip");
                if board.as_str() != name {
                    // This is likely a lab image. As of writing these are
                    // stored in the TUF repo for manufacturing but are
                    // explicitly ignored by the control plane, as they can
                    // never be used in an actual rack. The current thinking is
                    // that they will eventually no longer need to be in the TUF
                    // repo. Add these as an extra target, not an artifact.
                    self.targets
                        .entry(target_name)
                        .or_default()
                        .push(TargetSource::File(source));
                    return self;
                }
                target_name
            }
            _ => unreachable!(),
        };
        self.insert_artifact(target_name, version, tags, source);
        self
    }

    async fn guess_hubris_archive(
        file_start: &[u8],
        path: &Utf8Path,
    ) -> Option<(FileSource, CabooseData)> {
        if !file_start.starts_with(b"PK\x03\x04") {
            return None;
        }
        let mut source = FileSource::open(path.to_owned()).await.ok()?;
        let archive = source.read_hubris_archive().await.ok()?;
        let caboose = archive.read_caboose().ok()?;
        // HACK: We are reading the `image-name` file in the archive, which
        // appears to be "a" or "b" if it's an ROT image, "default" if it's
        // an SP image, and nonexistent if it's an ROT bootloader image. This
        // seems fragile. Ideally this can be in the caboose someday (see
        // sprot-release#74).
        let data = match archive.image_name().as_deref() {
            Ok("a") => CabooseData::new(
                &caboose,
                |caboose| {
                    KnownArtifactTags::from_rot_caboose(caboose, RotSlot::A)
                },
                path,
            ),
            Ok("b") => CabooseData::new(
                &caboose,
                |caboose| {
                    KnownArtifactTags::from_rot_caboose(caboose, RotSlot::B)
                },
                path,
            ),
            Ok("default") => CabooseData::new(
                &caboose,
                KnownArtifactTags::from_sp_caboose,
                path,
            ),
            Err(hubtools::Error::MissingFile(_, _)) => CabooseData::new(
                &caboose,
                KnownArtifactTags::from_rot_bootloader_caboose,
                path,
            ),
            _ => return None,
        };
        Some((source, data.ok()?))
    }

    pub async fn zone_image(self, path: Utf8PathBuf) -> Result<Self, Error> {
        let cloned_path = path.clone();
        let (file, layer_info) = tokio::task::spawn_blocking(move || {
            let file = try_path!(std::fs::File::open(&path), ReadFile, path);
            let mut archive = tar::Archive::new(GzDecoder::new(file));
            let layer_info = try_path!(
                Metadata::read_from_tar(&mut archive)
                    .and_then(|metadata| metadata.layer_info().cloned()),
                ReadZoneOxideJson,
                path
            );
            Ok::<_, Error>((archive.into_inner().into_inner(), layer_info))
        })
        .await??;
        let source = FileSource::from_file(file.into(), cloned_path);
        Ok(self.zone_image_inner(source, layer_info))
    }

    fn zone_image_inner(
        mut self,
        source: FileSource,
        LayerInfo { pkg, version }: LayerInfo,
    ) -> Self {
        let target_name = format!("zones/{pkg}.tar.gz");
        let tags = KnownArtifactTags::Zone { name: pkg };
        self.insert_artifact(target_name, version, tags, source);
        self
    }

    fn guess_zone_image(file_start: &[u8]) -> Option<LayerInfo> {
        // `oxide.json` is the first file of a zone image and is relatively
        // small, so it should be contained entirely within the first 4K of the
        // compressed tarball.
        let mut archive = tar::Archive::new(GzDecoder::new(file_start));
        Metadata::read_from_tar(&mut archive).ok()?.layer_info().ok().cloned()
    }

    /// Attempt to guess the artifact kind at `path` and add it to the
    /// repository.
    ///
    /// This should only be used as a convenience method to human users.
    /// Automation should not be making any guesses.
    pub async fn guess_artifact(
        self,
        path: Utf8PathBuf,
    ) -> Result<Self, Error> {
        if let Some(variant) = Self::guess_os_image(&path).await {
            return self.os_image_dir(variant, &path).await;
        }

        let mut file = try_path!(File::open(&path).await, OpenFile, path);
        let mut buf = [0; 4096];
        let n = try_path!(file.read(&mut buf).await, ReadFile, path);
        if n == 0 {
            // we're not going to try to guess an empty file
            return Err(ErrorKind::GuessArtifact { path }.into());
        }
        let buf = &buf[..n];
        let source = FileSource::from_file(file, path.clone());

        let (likely_corim, corim) = Self::guess_measurement_corpus(buf);
        if likely_corim {
            return self.measurement_corpus_inner(source, corim).await;
        }

        if let Some((source, data)) =
            Self::guess_hubris_archive(buf, &path).await
        {
            return Ok(self.hubris_archive_inner(source, data));
        }

        if let Some(layer_info) = Self::guess_zone_image(buf) {
            return Ok(self.zone_image_inner(source, layer_info));
        }

        Err(ErrorKind::GuessArtifact { path }.into())
    }

    fn insert_artifact(
        &mut self,
        target_name: String,
        version: ArtifactVersion,
        tags: KnownArtifactTags,
        source: FileSource,
    ) {
        self.targets
            .entry(target_name.clone())
            .or_default()
            .push(TargetSource::File(source));
        self.artifacts.entry(target_name.clone()).or_default().insert(
            ArtifactSchema { target_name, version, tags: tags.to_tags() },
        );
    }

    /// Add a non-artifact target to the repository.
    ///
    /// This target will be part of the signed set of files in the repository,
    /// but will not be copied onto sleds for use by the control plane. This is
    /// intended for ancillary files that are useful to systems other than the
    /// control plane.
    pub async fn extra_target(
        mut self,
        target_name: String,
        path: Utf8PathBuf,
    ) -> Result<Self, Error> {
        self.targets
            .entry(target_name.clone())
            .or_default()
            .push(TargetSource::File(FileSource::open(path).await?));
        Ok(self)
    }

    pub fn remove_target(mut self, target_name: &str) -> Self {
        self.targets.remove(target_name);
        self.artifacts.remove(target_name);
        self
    }

    pub fn fake_artifact(
        mut self,
        target_name: String,
        version: ArtifactVersion,
        tags: KnownArtifactTags,
        length: usize,
    ) -> Self {
        let prefix = format!("{target_name}\n{version}\n{tags:?}\n");
        self.targets
            .entry(target_name.clone())
            .or_default()
            .push(TargetSource::Fake(FakeSource::new(prefix, length)));
        self.artifacts.entry(target_name.clone()).or_default().insert(
            ArtifactSchema { target_name, version, tags: tags.to_tags() },
        );
        self
    }

    pub fn fake(system_version: Version) -> Result<Self, Error> {
        let version = ArtifactVersion::new(system_version.to_string())?;
        let mut editor = Self::new(system_version);

        for hash in ["123abc", "def456"] {
            editor = editor.fake_artifact(
                format!("measurements/corim-fake-{version}-{hash}.cbor"),
                version.clone(),
                KnownArtifactTags::MeasurementCorpus {},
                4 * KIB,
            );
        }
        for variant in [OsVariant::Host, OsVariant::Recovery] {
            for board in [OsBoard::Gimlet, OsBoard::Cosmo] {
                editor = editor.fake_artifact(
                    format!("os-{variant}/{board}.rom"),
                    version.clone(),
                    KnownArtifactTags::OsPhase1 { variant, board },
                    MIB,
                );
            }
            editor = editor.fake_artifact(
                format!("os-{variant}/zfs.img"),
                version.clone(),
                KnownArtifactTags::OsPhase2 { variant },
                4 * MIB,
            );
        }
        for slot in [RotSlot::A, RotSlot::B] {
            editor = editor.fake_artifact(
                format!("rot/fake-unsigned-{version}-slot-{slot}.zip"),
                version.clone(),
                KnownArtifactTags::Rot {
                    board: "fake".into(),
                    sign: Sign::UNSIGNED,
                    slot,
                },
                256 * KIB,
            );
        }
        editor = editor.fake_artifact(
            format!("rot-bootloader/fake-unsigned-{version}.zip"),
            version.clone(),
            KnownArtifactTags::RotBootloader {
                board: "fake".into(),
                sign: Sign::UNSIGNED,
            },
            64 * KIB,
        );
        editor = editor.fake_artifact(
            format!("sp/fake-{version}.zip"),
            version.clone(),
            KnownArtifactTags::Sp { board: "fake".into() },
            MIB,
        );
        for name in ["zone1", "zone2"] {
            editor = editor.fake_artifact(
                format!("zones/{name}.tar.gz"),
                version.clone(),
                KnownArtifactTags::Zone { name: name.into() },
                MIB,
            );
        }

        Ok(editor)
    }

    pub async fn metadata(
        mut self,
        key: String,
        value: serde_json::Value,
    ) -> Self {
        self.metadata.insert(key, value);
        self
    }

    pub async fn remove_metadata(mut self, key: &str) -> Self {
        self.metadata.remove(key);
        self
    }

    pub fn from_repo(repo: &'a Repository) -> Result<Self, Error> {
        Self::new(repo.system_version().clone()).import_repo(repo)
    }

    pub fn import_repo(mut self, repo: &'a Repository) -> Result<Self, Error> {
        if repo.is_v1() {
            return Err(ErrorKind::ImportV1Repo.into());
        }

        for (target_name, target) in repo.targets() {
            if target_name.raw() == ArtifactsSchema::TARGET_NAME {
                continue;
            }
            self.targets.entry(target_name.raw().to_owned()).or_default().push(
                TargetSource::Repository(RepositorySource {
                    repo,
                    target_name: target_name.raw().to_owned(),
                    length: target.length,
                    sha256: target.hashes.sha256.to_vec(),
                }),
            );
        }
        for artifact in repo.artifacts() {
            self.artifacts
                .entry(artifact.target_name.clone())
                .or_default()
                .insert(ArtifactSchema {
                    target_name: artifact.target_name.clone(),
                    version: artifact.version.clone(),
                    tags: artifact.tags.clone(),
                });
        }
        Ok(self)
    }

    pub async fn finish(self) -> Result<UnsignedRepository<'a>, Error> {
        // Un-nest `self.artifacts`, returning an error if we have multiple
        // artifact definitions for a single target name.
        let mut artifacts = self
            .artifacts
            .into_iter()
            .filter_map(|(target_name, entries)| {
                Some(if entries.len() > 1 {
                    Err(ErrorKind::TargetNameCollision { target_name }.into())
                } else {
                    Ok((target_name, entries.into_iter().next()?))
                })
            })
            .collect::<Result<BTreeMap<_, _>, Error>>()?;

        // Collect all the sha256 hashes and lengths for each source. For file
        // and fake sources, we want to calculate the hashes in parallel, so
        // we spawn their calculation tasks on a JoinSet. Sources from borrowed
        // repositories can't be moved into a task, but we already know their
        // hash.
        let mut all_targets = Vec::new();
        let mut tasks = JoinSet::new();
        for (target_name, sources) in self.targets {
            for source in sources {
                let target_name = target_name.clone();
                match source {
                    TargetSource::Bytes(source) => {
                        all_targets.push((target_name, source.into_target()));
                    }
                    TargetSource::File(source) => {
                        let future = source
                            .into_target()
                            .map_ok(|target| (target_name, target));
                        tasks.spawn(future);
                    }
                    TargetSource::Repository(source) => {
                        all_targets.push((target_name, source.into_target()));
                    }
                    TargetSource::Fake(source) => {
                        let future = source
                            .into_target()
                            .map(|target| Ok((target_name, target)));
                        tasks.spawn(future);
                    }
                }
            }
        }
        while let Some(result) = tasks.join_next().await {
            all_targets.push(result??);
        }
        // Fold the targets back into a map, checking that duplicates have the
        // same sha256 hash and length.
        let mut targets = TargetMap::default();
        for (target_name, target) in all_targets {
            targets.insert(target_name, target)?;
        }

        if self.generate_installinator_document {
            let version =
                ArtifactVersion::new(self.system_version.to_string())?;
            let target_name = format!("installinator_document-{version}.json");
            let artifact = ArtifactSchema {
                target_name: target_name.clone(),
                version,
                tags: KnownArtifactTags::InstallinatorDocument {}.to_tags(),
            };
            if let Some(existing) = artifacts.get(&target_name) {
                if existing != &artifact {
                    return Err(
                        ErrorKind::TargetNameCollision { target_name }.into()
                    );
                }
            } else {
                artifacts.insert(target_name.clone(), artifact);
            }

            let mut document = InstallinatorDocument { artifacts: Vec::new() };
            for artifact in artifacts.values() {
                if let Some(kind) = KnownArtifactTags::from_tags(&artifact.tags)
                    .ok()
                    .and_then(|tags| tags.to_installinator())
                    && let Some(file_name) =
                        Utf8Path::new(&artifact.target_name).file_name()
                    && let Some(target) = targets.0.get(&artifact.target_name)
                    && let Ok(sha256) = target.sha256.as_slice().try_into()
                {
                    document.artifacts.push(InstallinatorArtifact {
                        file_name: file_name.to_owned(),
                        kind,
                        sha256,
                    });
                }
            }
            let target = BytesSource::json(&document)
                .map_err(ErrorKind::SerializeInstallinator)?
                .into_target();
            targets.insert(target_name, target)?;
        }

        let document = ArtifactsSchema {
            system_version: self.system_version,
            artifacts: artifacts.into_values().collect(),
            metadata: self.metadata,
        };
        let target = BytesSource::json(&document)
            .map_err(ErrorKind::SerializeArtifacts)?
            .into_target();
        targets.insert(ArtifactsSchema::TARGET_NAME.to_owned(), target)?;
        Ok(UnsignedRepository::from_targets(targets.0))
    }
}

#[derive(Debug)]
struct CabooseData {
    tags: KnownArtifactTags,
    name: String,
    version: ArtifactVersion,
}

impl CabooseData {
    fn new<F>(
        caboose: &Caboose,
        tag_fn: F,
        path: &Utf8Path,
    ) -> Result<Self, Error>
    where
        F: FnOnce(&Caboose) -> Result<KnownArtifactTags, ReadCabooseError>,
    {
        let tags = try_path!(tag_fn(caboose), ReadCaboose, path);
        let name = try_path!(
            tufaceous_artifact::hubris::read_name(caboose),
            ReadCaboose,
            path
        );
        let version = try_path!(
            tufaceous_artifact::hubris::read_version(caboose),
            ReadCaboose,
            path
        );
        Ok(Self {
            tags,
            name: name.to_owned(),
            version: ArtifactVersion::new(version)?,
        })
    }
}

#[derive(Debug, Default)]
struct TargetMap<'a>(BTreeMap<String, Target<'a>>);

impl<'a> TargetMap<'a> {
    fn insert(
        &mut self,
        target_name: String,
        target: Target<'a>,
    ) -> Result<(), Error> {
        if let Some(existing) = self.0.get(&target_name) {
            if existing.length == target.length
                && existing.sha256 == target.sha256
            {
                if existing.source.cost() <= target.source.cost() {
                    return Ok(());
                }
            } else {
                return Err(
                    ErrorKind::TargetNameCollision { target_name }.into()
                );
            }
        }
        self.0.insert(target_name, target);
        Ok(())
    }
}
