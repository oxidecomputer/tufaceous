// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;

use camino::Utf8Path;
use camino::Utf8PathBuf;
use futures_util::FutureExt;
use futures_util::TryFutureExt;
use futures_util::TryStreamExt;
use hubtools::Caboose;
use semver::Version;
use tokio::fs::File;
use tokio::task::JoinSet;
use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::InstallinatorArtifact;
use tufaceous_artifact::InstallinatorDocument;
use tufaceous_artifact::KnownArtifactTags;
use tufaceous_artifact::OsBoard;
use tufaceous_artifact::OsVariant;
use tufaceous_artifact::RotSlot;
use tufaceous_artifact::hubris::ReadCabooseError;

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
use crate::schema::ArtifactSchema;
use crate::schema::ArtifactsSchema;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

#[derive(Debug)]
pub struct RepositoryEditor<'a> {
    system_version: Version,
    targets: HashMap<String, Vec<TargetSource<'a>>>,
    artifacts: HashMap<String, HashSet<ArtifactSchema>>,
    metadata: BTreeMap<String, serde_json::Value>,
    generate_installinator_document: bool,
}

impl<'a> RepositoryEditor<'a> {
    pub fn new(system_version: Version) -> Self {
        Self {
            system_version,
            targets: HashMap::new(),
            artifacts: HashMap::new(),
            metadata: BTreeMap::new(),
            generate_installinator_document: false,
        }
    }

    pub fn system_version(self, system_version: Version) -> Self {
        Self { system_version, ..self }
    }

    pub async fn add_artifact(
        mut self,
        target_name: String,
        version: ArtifactVersion,
        tags: KnownArtifactTags,
        path: impl Into<Utf8PathBuf>,
    ) -> Result<Self, Error> {
        self.targets
            .entry(target_name.clone())
            .or_default()
            .push(TargetSource::File(FileSource::open(path).await?));
        self.artifacts.entry(target_name.clone()).or_default().insert(
            ArtifactSchema { target_name, version, tags: tags.to_tags() },
        );
        Ok(self)
    }

    pub async fn add_extra_target(
        mut self,
        target_name: String,
        path: impl Into<Utf8PathBuf>,
    ) -> Result<Self, Error> {
        self.targets
            .entry(target_name.clone())
            .or_default()
            .push(TargetSource::File(FileSource::open(path).await?));
        Ok(self)
    }

    pub fn add_fake_artifact(
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
        let mut editor =
            Self::new(system_version).generate_installinator_document();

        for hash in ["123abc", "def456"] {
            editor = editor.add_fake_artifact(
                format!("measurement-corpus-{hash}.corim"),
                version.clone(),
                KnownArtifactTags::MeasurementCorpus {},
                4 * KIB,
            );
        }
        for variant in [OsVariant::Host, OsVariant::Recovery] {
            for board in [OsBoard::Gimlet, OsBoard::Cosmo] {
                editor = editor.add_fake_artifact(
                    format!("{variant}-os/{board}.rom"),
                    version.clone(),
                    KnownArtifactTags::OsPhase1 { variant, board },
                    MIB,
                );
            }
            editor = editor.add_fake_artifact(
                format!("{variant}-os/zfs.img"),
                version.clone(),
                KnownArtifactTags::OsPhase2 { variant },
                4 * MIB,
            );
        }
        for slot in [RotSlot::A, RotSlot::B] {
            editor = editor.add_fake_artifact(
                format!("rot-fake-slot{slot}.zip"),
                version.clone(),
                KnownArtifactTags::Rot {
                    board: "fake".into(),
                    sign: None,
                    slot,
                },
                256 * KIB,
            );
        }
        editor = editor.add_fake_artifact(
            "rot-bootloader-fake.zip".into(),
            version.clone(),
            KnownArtifactTags::RotBootloader {
                board: "fake".into(),
                sign: None,
            },
            64 * KIB,
        );
        editor = editor.add_fake_artifact(
            "sp-fake.zip".into(),
            version.clone(),
            KnownArtifactTags::Sp { board: "fake".into() },
            MIB,
        );
        for name in ["zone1", "zone2"] {
            editor = editor.add_fake_artifact(
                format!("zones/{name}.tar.gz"),
                version.clone(),
                KnownArtifactTags::Zone { name: name.into() },
                MIB,
            );
        }

        Ok(editor)
    }

    pub fn from_repo(repo: &'a mut Repository) -> Result<Self, Error> {
        Self::new(repo.system_version().clone()).import_repo(repo)
    }

    pub fn import_repo(
        mut self,
        repo: &'a mut Repository,
    ) -> Result<Self, Error> {
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

    pub fn generate_installinator_document(self) -> Self {
        Self { generate_installinator_document: true, ..self }
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
                    && let Some(target) = targets.0.get(&artifact.target_name)
                    && let Ok(sha256) = target.sha256.as_slice().try_into()
                {
                    document.artifacts.push(InstallinatorArtifact {
                        name: artifact.target_name.clone(),
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

    pub async fn add_os_artifacts(
        mut self,
        variant: OsVariant,
        build_output_path: impl Into<Utf8PathBuf>,
    ) -> Result<Self, Error> {
        let base = Utf8Path::new(match variant {
            OsVariant::Host => "host-os",
            OsVariant::Recovery => "recovery-os",
        });
        let version = ArtifactVersion::new(self.system_version.to_string())?;
        let mut read_dir = crate::util::read_dir(build_output_path).await?;
        while let Some(entry) = read_dir.try_next().await? {
            let target_name = base.join(entry.file_name());
            let tags = match entry.file_name() {
                "cosmo.rom" => KnownArtifactTags::OsPhase1 {
                    variant,
                    board: OsBoard::Cosmo,
                },
                "gimlet.rom" => KnownArtifactTags::OsPhase1 {
                    variant,
                    board: OsBoard::Gimlet,
                },
                "zfs.img" => KnownArtifactTags::OsPhase2 { variant },

                _ => {
                    self = self
                        .add_extra_target(target_name.into(), entry.into_path())
                        .await?;
                    continue;
                }
            };
            self = self
                .add_artifact(
                    target_name.into(),
                    version.clone(),
                    tags,
                    entry.into_path(),
                )
                .await?;
        }
        Ok(self)
    }

    async fn add_hubris_image<F>(
        mut self,
        target_name: String,
        path: impl Into<Utf8PathBuf>,
        f: F,
    ) -> Result<Self, Error>
    where
        F: FnOnce(&Caboose) -> Result<KnownArtifactTags, ReadCabooseError>,
    {
        let path = path.into();
        let mut source = FileSource::open(path.clone()).await?;
        let caboose = source.read_hubris_caboose().await?;
        self.targets
            .entry(target_name.clone())
            .or_default()
            .push(TargetSource::File(source));
        let (tags, version) = f(&caboose)
            .and_then(|tags| {
                Ok((tags, tufaceous_artifact::hubris::read_version(&caboose)?))
            })
            .map_err(|source| ErrorKind::ReadCaboose { source, path })?;
        let version = ArtifactVersion::new(version)?;
        self.artifacts.entry(target_name.clone()).or_default().insert(
            ArtifactSchema { target_name, version, tags: tags.to_tags() },
        );
        Ok(self)
    }

    pub async fn add_rot_image(
        self,
        target_name: String,
        slot: RotSlot,
        path: impl Into<Utf8PathBuf>,
    ) -> Result<Self, Error> {
        self.add_hubris_image(target_name, path, |caboose| {
            KnownArtifactTags::from_rot_caboose(caboose, slot)
        })
        .await
    }

    pub async fn add_rot_bootloader_image(
        self,
        target_name: String,
        path: impl Into<Utf8PathBuf>,
    ) -> Result<Self, Error> {
        self.add_hubris_image(
            target_name,
            path,
            KnownArtifactTags::from_rot_bootloader_caboose,
        )
        .await
    }

    pub async fn add_sp_image(
        self,
        target_name: String,
        path: impl Into<Utf8PathBuf>,
    ) -> Result<Self, Error> {
        self.add_hubris_image(
            target_name,
            path,
            KnownArtifactTags::from_sp_caboose,
        )
        .await
    }

    pub async fn add_zone_image(
        mut self,
        file_name: &str,
        path: impl Into<Utf8PathBuf>,
    ) -> Result<Self, Error> {
        let path = path.into();
        let file = File::open(&path)
            .await
            .map_err(|source| ErrorKind::OpenFile {
                source,
                path: path.clone(),
            })?
            .into_std()
            .await;
        let (file, layer_info) =
            crate::util::read_zone_layer_info(file, path.clone()).await?;
        let source = FileSource::from_file(file.into(), path);
        let target_name = format!("zones/{file_name}");
        self.targets
            .entry(target_name.clone())
            .or_default()
            .push(TargetSource::File(source));
        self.artifacts.entry(target_name.clone()).or_default().insert(
            ArtifactSchema {
                target_name,
                version: layer_info.version,
                tags: KnownArtifactTags::Zone { name: layer_info.pkg }
                    .to_tags(),
            },
        );
        Ok(self)
    }

    pub async fn insert_metadata(
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
}

#[derive(Default)]
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
