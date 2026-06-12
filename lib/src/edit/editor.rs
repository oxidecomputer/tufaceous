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
use tufaceous_artifact::ArtifactHash;
use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::InstallinatorDocument;
use tufaceous_artifact::KnownArtifactTags;
use tufaceous_artifact::Metadata;
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
use crate::schema::ArtifactSetSchema;

#[derive(Debug, Clone)]
#[must_use]
pub struct RepositoryEditor<'a> {
    system_version: Version,
    artifact_version: ArtifactVersion,
    generate_installinator_document: bool,
    targets: HashMap<String, Vec<TargetSource<'a>>>,
    artifacts: HashMap<String, HashSet<ArtifactSchema>>,
    metadata: BTreeMap<String, String>,
}

impl<'a> RepositoryEditor<'a> {
    /// Create an empty repository editor.
    pub fn new(system_version: Version) -> Result<Self, Error> {
        Ok(Self {
            artifact_version: ArtifactVersion::new(system_version.to_string())?,
            system_version,
            generate_installinator_document: true,
            targets: HashMap::new(),
            artifacts: HashMap::new(),
            metadata: BTreeMap::new(),
        })
    }

    /// Change the system version of the repository.
    pub fn set_system_version(
        self,
        system_version: Version,
    ) -> Result<Self, Error> {
        Ok(Self {
            artifact_version: ArtifactVersion::new(system_version.to_string())?,
            system_version,
            ..self
        })
    }

    /// Sets whether an Installinator document should be generated based on the
    /// artifacts in the repository.
    ///
    /// Defaults to `true`. The document is generated during
    /// [`RepositoryEditor::finish`].
    pub fn set_generate_installinator_document(
        self,
        generate_installinator_document: bool,
    ) -> Self {
        Self { generate_installinator_document, ..self }
    }

    /// Add a measurement corpus to the repository.
    pub async fn add_measurement_corpus(
        self,
        path: impl Into<Utf8PathBuf>,
    ) -> Result<Self, Error> {
        let source = FileSource::open(path.into()).await?;
        let input = Input::measurement_corpus(source, None).await?;
        self.insert_input(input)
    }

    /// Add a fake measurement corpus to the repository.
    ///
    /// `hashes` specifies the number of SHA256 hashes to list in the CoRIM
    /// document. This can be used to create different documents at the same
    /// version.
    pub fn add_fake_measurement_corpus(
        self,
        hashes: usize,
        version: ArtifactVersion,
    ) -> Result<Self, Error> {
        let input = Input::fake_measurement_corpus(hashes, version, None)?;
        self.insert_input(input)
    }

    /// Add an OS image to the repository.
    ///
    /// `output_dir` is a path to the output directory for `helios-build image`
    /// (the `-o` argument). This directory contains `cosmo.rom`, `gimlet.rom`,
    /// and `zfs.img`.
    pub async fn add_os_image_dir(
        self,
        variant: OsVariant,
        output_dir: impl AsRef<Utf8Path>,
    ) -> Result<Self, Error> {
        let input = Input::os_images(
            variant,
            output_dir.as_ref(),
            None,
            self.artifact_version.clone(),
        )
        .await?;
        self.insert_input(input)
    }

    /// Add a fake OS image to the repository.
    pub fn add_fake_os_image(self, variant: OsVariant) -> Result<Self, Error> {
        let input =
            Input::fake_os_images(variant, self.artifact_version.clone(), None);
        self.insert_input(input)
    }

    /// Add a Root of Trust Hubris archive to the repository.
    ///
    /// Tags are automatically determined based on the image caboose, except
    /// for `slot` which must be specified.
    pub async fn add_rot_archive(
        self,
        rot_slot: RotSlot,
        path: impl Into<Utf8PathBuf>,
    ) -> Result<Self, Error> {
        let source = FileSource::open(path.into()).await?;
        self.insert_input(Input::rot_archive(source, None, rot_slot).await?)
    }

    /// Add a Root of Trust Bootloader Hubris archive to the repository.
    ///
    /// Tags are automatically determined based on the image caboose.
    pub async fn add_rot_bootloader_archive(
        self,
        path: impl Into<Utf8PathBuf>,
    ) -> Result<Self, Error> {
        let source = FileSource::open(path.into()).await?;
        self.insert_input(Input::rot_bootloader_archive(source, None).await?)
    }

    /// Add a Service Processor Hubris archive to the repository.
    ///
    /// Tags are automatically determined based on the image caboose.
    pub async fn add_sp_archive(
        self,
        path: impl Into<Utf8PathBuf>,
    ) -> Result<Self, Error> {
        let source = FileSource::open(path.into()).await?;
        self.insert_input(Input::sp_archive(source, None).await?)
    }

    /// Add a fake Root of Trust Hubris archive to the repository.
    ///
    /// This will generate a fake Hubris archive with the appropriate tags.
    pub fn add_fake_rot_archive(self, tags: RotTags) -> Result<Self, Error> {
        let input =
            Input::fake_rot_archive(tags, self.artifact_version.clone(), None)?;
        self.insert_input(input)
    }

    /// Add a fake Root of Trust Bootloader Hubris archive to the repository.
    ///
    /// This will generate a fake Hubris archive with the appropriate tags.
    pub fn add_fake_rot_bootloader_archive(
        self,
        tags: RotBootloaderTags,
    ) -> Result<Self, Error> {
        let input = Input::fake_rot_bootloader_archive(
            tags,
            self.artifact_version.clone(),
            None,
        )?;
        self.insert_input(input)
    }

    /// Add a fake Service Processor Hubris archive to the repository.
    ///
    /// This will generate a fake Hubris archive with the appropriate tags.
    pub fn add_fake_sp_archive(self, tags: SpTags) -> Result<Self, Error> {
        let input =
            Input::fake_sp_archive(tags, self.artifact_version.clone(), None)?;
        self.insert_input(input)
    }

    /// Add a zone image to the repository.
    ///
    /// The `zone_name` tag is automatically determined based on the layer
    /// metadata (the `oxide.json` file that starts zone tarballs).
    pub async fn add_zone_image(
        self,
        path: impl Into<Utf8PathBuf>,
    ) -> Result<Self, Error> {
        self.insert_input(Input::zone_image(path.into()).await?)
    }

    /// Add a fake zone image to the repository.
    ///
    /// This will generate a tarball containing a matching `oxide.json` layer
    /// metadata file.
    pub fn add_fake_zone_image(
        self,
        zone_name: String,
        file_name: String,
    ) -> Result<Self, Error> {
        let input = Input::fake_zone_image(
            zone_name,
            file_name,
            self.artifact_version.clone(),
            None,
        )?;
        self.insert_input(input)
    }

    /// Attempt to guess the artifact kind at `path` and add it to the
    /// repository.
    ///
    /// This should only be used as a convenience method to human users.
    /// Automation should not be making any guesses.
    pub async fn guess_artifact(
        self,
        path: impl Into<Utf8PathBuf>,
    ) -> Result<Self, Error> {
        let input =
            Input::guess(path.into(), self.artifact_version.clone()).await?;
        self.insert_input(input)
    }

    fn insert_input<T>(mut self, input: Input<T>) -> Result<Self, Error>
    where
        T: Into<TargetSource<'a>>,
    {
        for output in input.outputs()? {
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
        Ok(self)
    }

    /// Add a non-artifact target to the repository.
    ///
    /// This target will be part of the signed set of files in the repository,
    /// but will not be copied onto sleds for use by the control plane. This is
    /// intended for ancillary files that are useful to systems other than the
    /// control plane.
    pub async fn add_extra_target(
        mut self,
        target_name: impl Into<String>,
        path: impl Into<Utf8PathBuf>,
    ) -> Result<Self, Error> {
        self.targets
            .entry(target_name.into())
            .or_default()
            .push(FileSource::open(path.into()).await?.into());
        Ok(self)
    }

    /// Remove artifacts matching the given tags.
    pub fn remove_artifacts(
        mut self,
        filter: &KnownArtifactTags,
    ) -> Result<Self, Error> {
        let filter =
            filter.to_tags().map_err(ErrorKind::ConvertKnownTagsToMap)?;
        let removed = self.artifacts.extract_if(|_, artifacts| {
            artifacts.retain(|artifact| artifact.tags != filter);
            artifacts.is_empty() // extract_if: remove from map if true
        });
        for (target_name, _) in removed {
            self.targets.remove(&target_name);
        }
        Ok(self)
    }

    /// Remove a target with the given target name.
    pub fn remove_target(mut self, target_name: impl AsRef<str>) -> Self {
        let target_name = target_name.as_ref();
        self.targets.remove(target_name);
        self.artifacts.remove(target_name);
        self
    }

    /// Create a fake repository for testing purposes.
    pub fn fake(system_version: Version) -> Result<Self, Error> {
        let mut editor = Self::new(system_version)?;
        let version = editor.artifact_version.clone();
        for input in Input::fake(&version, None)? {
            editor = editor.insert_input(input)?;
        }
        Ok(editor)
    }

    /// Create a fake repository for testing purposes where the system version,
    /// artifact versions, and the versions interior to the artifact data are
    /// potentially different.
    ///
    /// The Installinator document, if generated, always uses `system_version`
    /// for the artifact and interior versions.
    pub fn inconsistent_fake(
        system_version: Version,
        artifact_version: &ArtifactVersion,
        interior_version: &ArtifactVersion,
    ) -> Result<Self, Error> {
        let mut editor = Self::new(system_version)?;
        for input in Input::fake(artifact_version, Some(interior_version))? {
            editor = editor.insert_input(input)?;
        }
        Ok(editor)
    }

    /// Set the repository-level metadata.
    pub fn set_metadata(mut self, metadata: &Metadata) -> Result<Self, Error> {
        self.metadata =
            metadata.to_map().map_err(ErrorKind::ConvertMetadataToMap)?;
        Ok(self)
    }

    /// Create a `RepositoryEditor` from a loaded repository.
    ///
    /// This creates an editor with references to all of the artifacts and
    /// targets in the original repository.
    pub fn from_repo(repo: &'a Repository) -> Result<Self, Error> {
        Self::new(repo.system_version().clone())?.import_repo(repo)
    }

    /// Import all of the artifacts and targets from a repository into this
    /// editor.
    pub fn import_repo(mut self, repo: &'a Repository) -> Result<Self, Error> {
        for artifact in repo.to_artifact_schema()? {
            self.artifacts
                .entry(artifact.target_name.clone())
                .or_default()
                .insert(artifact);
        }
        for (target_name, target) in repo.targets() {
            if target_name.raw() == ArtifactSetSchema::TARGET_NAME {
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
        self.metadata = repo.metadata().clone();
        Ok(self)
    }

    /// Finalize the artifacts and targets, returning an [`UnsignedRepository`].
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

        // Ensure each set of tags is unique, except for known tag sets that
        // we expect to be non-unique.
        let mut seen_tags = HashMap::new();
        for (target_name, artifact) in &artifacts {
            if let Some(tags) = artifact.known_tags()
                && tags.allow_multiple_artifacts()
            {
                continue;
            }

            if let Some(first_target_name) =
                seen_tags.insert(&artifact.tags, target_name)
            {
                return Err(ErrorKind::DisallowedTagCollision {
                    first_target_name: first_target_name.clone(),
                    second_target_name: target_name.clone(),
                    tags: artifact.tags.clone(),
                }
                .into());
            }
        }

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
                self.artifact_version.clone(),
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

        let document = ArtifactSetSchema {
            system_version: self.system_version,
            artifacts: artifacts.into_values().collect(),
            metadata: self.metadata,
        };
        let target = BytesSource::json(&document)
            .map_err(ErrorKind::SerializeArtifacts)?
            .into_target()
            .await;
        targets.insert(ArtifactSetSchema::TARGET_NAME.to_owned(), target)?;
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
    let mut document = InstallinatorDocument::empty(version.clone());
    for (artifact, hash) in artifacts {
        let artifact = artifact.as_ref();
        if let Ok(hash) = hash.as_ref().try_into().map(ArtifactHash)
            && let Some(artifact) = crate::util::installinator_artifact(
                artifact.tags.clone(),
                hash,
                &artifact.target_name,
            )
        {
            document.artifacts.insert(artifact);
        }
    }
    let source = BytesSource::json(&document)
        .map_err(ErrorKind::SerializeInstallinator)?;
    Output::new(
        target_name,
        version,
        &KnownArtifactTags::InstallinatorDocument,
        source,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bytes::Bytes;
    use chrono::Utc;
    use futures_util::TryStreamExt;
    use semver::Version;
    use tufaceous_artifact::ArtifactVersion;

    use crate::RepositoryLoader;
    use crate::TrustStoreBehavior;
    use crate::edit::RepositoryEditor;
    use crate::edit::source::BytesSource;
    use crate::error::Error;
    use crate::schema::ArtifactSchema;

    /// Test that all of the repository creation and loading machinery works
    /// when an artifact is zero bytes. (This otherwise wouldn't be tested as
    /// none of the fake artifacts are empty.)
    #[tokio::test]
    async fn empty_artifact() -> Result<(), Error> {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let mut editor = RepositoryEditor::new(Version::new(1, 0, 0))?
            .set_generate_installinator_document(false);
        // Manually add an empty artifact.
        let target_name = "empty".to_string();
        editor
            .targets
            .entry(target_name.clone())
            .or_default()
            .push(BytesSource::new(Bytes::new()).into());
        editor.artifacts.entry(target_name.clone()).or_default().insert(
            ArtifactSchema {
                target_name,
                version: ArtifactVersion::new_const("1.0.0"),
                tags: BTreeMap::new(),
            },
        );

        let zip = editor
            .finish()
            .await?
            .generate_root()
            .sign()
            .await?
            .write_zip(Vec::new(), Utc::now())
            .await?;
        let repo = RepositoryLoader::new()
            .trust_store_behavior(TrustStoreBehavior::UnsafeBlindFaith)
            .load_zip_buffer(zip, &log)
            .await?;
        let artifacts = repo.artifacts().iter().collect::<Vec<_>>();
        assert_eq!(artifacts.len(), 1);
        let data = repo
            .read_artifact(artifacts[0])
            .await?
            .map_ok(|bytes| bytes.to_vec())
            .try_concat()
            .await?;
        assert!(data.is_empty());
        Ok(())
    }
}
