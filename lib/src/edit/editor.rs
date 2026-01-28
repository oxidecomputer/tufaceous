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
use semver::Version;
use tokio::task::JoinSet;
use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::ArtifactVersionError;
use tufaceous_artifact::InstallinatorArtifact;
use tufaceous_artifact::InstallinatorDocument;
use tufaceous_artifact::KnownArtifactTags;
use tufaceous_artifact::OsVariant;
use tufaceous_artifact::RotBootloaderTags;
use tufaceous_artifact::RotSlot;
use tufaceous_artifact::RotTags;
use tufaceous_artifact::SpTags;

use crate::Repository;
use crate::edit::UnsignedRepository;
use crate::edit::input::Input;
use crate::edit::input::Output;
use crate::edit::source::BytesSource;
use crate::edit::source::FileSource;
use crate::edit::source::RepositorySource;
use crate::edit::source::Target;
use crate::edit::source::TargetSource;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::schema::ArtifactSchema;
use crate::schema::ArtifactsSchema;

#[derive(Debug)]
pub struct RepositoryEditor<'a> {
    system_version: Version,
    artifact_version: Result<ArtifactVersion, ArtifactVersionError>,
    generate_installinator_document: bool,
    targets: HashMap<String, Vec<TargetSource<'a>>>,
    artifacts: HashMap<String, HashSet<ArtifactSchema>>,
    metadata: BTreeMap<String, serde_json::Value>,
}

impl<'a> RepositoryEditor<'a> {
    /// Create an empty repository editor.
    pub fn new(system_version: Version) -> Self {
        Self {
            artifact_version: ArtifactVersion::new(system_version.to_string()),
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
        let source = FileSource::open(path).await?;
        let input = Input::measurement_corpus(
            source,
            None,
            self.artifact_version.clone()?,
        )
        .await?;
        Ok(self.insert_input(input))
    }

    pub fn fake_measurement_corpus(self, hashes: usize) -> Result<Self, Error> {
        let input = Input::fake_measurement_corpus(
            hashes,
            self.artifact_version.clone()?,
        )?;
        Ok(self.insert_input(input))
    }

    /// Add an OS image to the repository.
    ///
    /// `output_dir` is a path to the output directory for `helios-build image`
    /// (the `-o` argument). This directory contains `cosmo.rom`, `gimlet.rom`,
    /// and `zfs.img`.
    pub async fn os_image_dir(
        self,
        variant: OsVariant,
        output_dir: &Utf8Path,
    ) -> Result<Self, Error> {
        let input = Input::os_images(
            variant,
            output_dir,
            None,
            self.artifact_version.clone()?,
        )
        .await?;
        Ok(self.insert_input(input))
    }

    pub fn fake_os_image(self, variant: OsVariant) -> Result<Self, Error> {
        let input =
            Input::fake_os_images(variant, self.artifact_version.clone()?);
        Ok(self.insert_input(input))
    }

    pub async fn rot_archive(
        self,
        slot: RotSlot,
        path: Utf8PathBuf,
    ) -> Result<Self, Error> {
        let source = FileSource::open(path).await?;
        Ok(self.insert_input(Input::rot_archive(source, None, slot).await?))
    }

    pub async fn rot_bootloader_archive(
        self,
        path: Utf8PathBuf,
    ) -> Result<Self, Error> {
        let source = FileSource::open(path).await?;
        Ok(self
            .insert_input(Input::rot_bootloader_archive(source, None).await?))
    }

    pub async fn sp_archive(self, path: Utf8PathBuf) -> Result<Self, Error> {
        let source = FileSource::open(path).await?;
        Ok(self.insert_input(Input::sp_archive(source, None).await?))
    }

    pub fn fake_rot_archive(self, tags: RotTags) -> Result<Self, Error> {
        let input =
            Input::fake_rot_archive(tags, self.artifact_version.clone()?)?;
        Ok(self.insert_input(input))
    }

    pub fn fake_rot_bootloader_archive(
        self,
        tags: RotBootloaderTags,
    ) -> Result<Self, Error> {
        let input = Input::fake_rot_bootloader_archive(
            tags,
            self.artifact_version.clone()?,
        )?;
        Ok(self.insert_input(input))
    }

    pub fn fake_sp_archive(self, tags: SpTags) -> Result<Self, Error> {
        let input =
            Input::fake_sp_archive(tags, self.artifact_version.clone()?)?;
        Ok(self.insert_input(input))
    }

    pub async fn zone_image(self, path: Utf8PathBuf) -> Result<Self, Error> {
        Ok(self.insert_input(Input::zone_image(path).await?))
    }

    pub fn fake_zone_image(self, name: String) -> Result<Self, Error> {
        let input =
            Input::fake_zone_image(name, self.artifact_version.clone()?)?;
        Ok(self.insert_input(input))
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
        let input = Input::guess(path, self.artifact_version.clone()?).await?;
        Ok(self.insert_input(input))
    }

    fn insert_input<T>(mut self, input: Input<T>) -> Self
    where
        T: Into<TargetSource<'a>>,
    {
        for output in input.outputs() {
            if let Some(artifact) = output.to_artifact_schema() {
                self.artifacts
                    .entry(artifact.target_name.clone())
                    .or_default()
                    .insert(artifact);
            }
            self.targets
                .entry(output.target_name)
                .or_default()
                .push(output.source.into());
        }
        self
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
            .entry(target_name)
            .or_default()
            .push(FileSource::open(path).await?.into());
        Ok(self)
    }

    pub fn remove_target(mut self, target_name: &str) -> Self {
        self.targets.remove(target_name);
        self.artifacts.remove(target_name);
        self
    }

    /// Manually adds a fake artifact. Don't use this if building a real
    /// repository; use one of the other `fake_*` methods instead.
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
            .push(BytesSource::fake_padded(prefix, length).into());
        self.artifacts.entry(target_name.clone()).or_default().insert(
            ArtifactSchema { target_name, version, tags: tags.to_tags() },
        );
        self
    }

    pub fn fake(system_version: Version) -> Result<Self, Error> {
        let mut editor = Self::new(system_version);
        let version = editor.artifact_version.clone()?;
        for input in Input::fake(&version)? {
            editor = editor.insert_input(input);
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
                RepositorySource {
                    repo,
                    target_name: target_name.raw().to_owned(),
                    length: target.length,
                    sha256: target.hashes.sha256.to_vec(),
                }
                .into(),
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
                        let future = source
                            .into_target()
                            .map(|target| Ok((target_name, target)));
                        tasks.spawn(future);
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
            let output = generate_installinator_document(
                artifacts.values().filter_map(|artifact| {
                    let target = targets.0.get(&artifact.target_name)?;
                    Some((artifact, target.sha256.as_slice()))
                }),
                self.artifact_version.clone()?,
            )?;
            if let Some(artifact) = output.to_artifact_schema() {
                if let Some(existing) = artifacts.get(&artifact.target_name) {
                    if existing != &artifact {
                        return Err(ErrorKind::TargetNameCollision {
                            target_name: artifact.target_name,
                        }
                        .into());
                    }
                } else {
                    artifacts.insert(artifact.target_name.clone(), artifact);
                }
            }
            targets.insert(
                output.target_name,
                output.source.into_target().await,
            )?;
        }

        let document = ArtifactsSchema {
            system_version: self.system_version,
            artifacts: artifacts.into_values().collect(),
            metadata: self.metadata,
        };
        let target = BytesSource::json(&document)
            .map_err(ErrorKind::SerializeArtifacts)?
            .into_target()
            .await;
        targets.insert(ArtifactsSchema::TARGET_NAME.to_owned(), target)?;
        Ok(UnsignedRepository::from_targets(targets.0))
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

pub(crate) fn generate_installinator_document(
    artifacts: impl Iterator<Item = (impl AsRef<ArtifactSchema>, impl AsRef<[u8]>)>,
    version: ArtifactVersion,
) -> Result<Output<BytesSource>, Error> {
    let target_name = format!("installinator_document-{version}.json");
    let mut document = InstallinatorDocument::default();
    for (artifact, sha256) in artifacts {
        let artifact = artifact.as_ref();
        if let Ok(tags) = KnownArtifactTags::from_tags(&artifact.tags)
            && let Some(kind) = tags.to_installinator()
            && let Some(file_name) =
                Utf8Path::new(&artifact.target_name).file_name()
            && let Ok(sha256) = sha256.as_ref().try_into()
        {
            document.artifacts.insert(InstallinatorArtifact {
                file_name: file_name.to_owned(),
                kind,
                sha256,
            });
        }
    }
    let source = BytesSource::json(&document)
        .map_err(ErrorKind::SerializeInstallinator)?;
    Ok(Output::new(
        target_name,
        version,
        KnownArtifactTags::InstallinatorDocument,
        source,
    ))
}
