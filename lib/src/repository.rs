// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use anyhow::{Context, Result, anyhow};
use buf_list::BufList;
use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, Utc};
use fs_err as fs;
use futures::TryStreamExt;
use semver::Version;
use tough::editor::RepositoryEditor;
use tough::editor::signed::SignedRole;
use tough::error::Error;
use tough::schema::{Root, Target};
use tough::{ExpirationEnforcement, Repository, RepositoryLoader, TargetName};
use tufaceous_artifact::{
    Artifact, ArtifactHash, ArtifactVersion, ArtifactsDocument,
};
use url::Url;

use crate::assemble::{
    ArtifactDeploymentUnits, DeploymentUnitData, DeploymentUnitMapBuilder,
    DeploymentUnitScope,
};
use crate::key::Key;
use crate::target::TargetWriter;
use crate::utils::merge_anyhow_list;
use crate::{AddArtifact, ArchiveBuilder};

/// A TUF repository describing Omicron.
#[derive(Debug)]
pub struct OmicronRepo {
    log: slog::Logger,
    repo: Repository,
    repo_path: Utf8PathBuf,
}

impl OmicronRepo {
    /// Initializes a new repository at the given path, writing it to disk.
    pub async fn initialize(
        log: &slog::Logger,
        repo_path: &Utf8Path,
        system_version: Version,
        keys: Vec<Key>,
        root: Option<SignedRole<Root>>,
        expiry: DateTime<Utc>,
    ) -> Result<Self> {
        let root = match root {
            Some(root) => root,
            None => crate::root::new_root(keys.clone(), expiry).await?,
        };
        let editor = OmicronRepoEditor::initialize(
            repo_path.to_owned(),
            root,
            system_version,
        )
        .await?;

        editor
            .sign_and_finish(keys, expiry)
            .await
            .context("error signing new repository")?;

        // In theory we "trust" the key we just used to sign this repository,
        // but the code path is equivalent to `load_untrusted`.
        Self::load_untrusted(log, repo_path).await
    }

    /// Loads a repository from the given path.
    ///
    /// This method enforces expirations. To load without expiration enforcement, use
    /// [`Self::load_ignore_expiration`].
    pub async fn load(
        log: &slog::Logger,
        repo_path: &Utf8Path,
        trusted_roots: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Result<Self> {
        Self::load_impl(
            log,
            repo_path,
            trusted_roots,
            ExpirationEnforcement::Safe,
        )
        .await
    }

    /// Loads a repository from the given path, ignoring expiration.
    ///
    /// Use cases for this include:
    ///
    /// 1. When you're editing an existing repository and will re-sign it afterwards.
    /// 2. When you're reading a repository that was uploaded out-of-band,
    ///    instead of fetched from a network-accessible repository
    /// 3. In an environment in which time isn't available.
    pub async fn load_ignore_expiration(
        log: &slog::Logger,
        repo_path: &Utf8Path,
        trusted_roots: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Result<Self> {
        Self::load_impl(
            log,
            repo_path,
            trusted_roots,
            ExpirationEnforcement::Unsafe,
        )
        .await
    }

    async fn load_impl(
        log: &slog::Logger,
        repo_path: &Utf8Path,
        trusted_roots: impl IntoIterator<Item = impl AsRef<[u8]>>,
        exp: ExpirationEnforcement,
    ) -> Result<Self> {
        let repo_path = repo_path.canonicalize_utf8()?;
        let mut verify_error = None;
        for root in trusted_roots {
            match RepositoryLoader::new(
                &root,
                Url::from_file_path(repo_path.join("metadata"))
                    .expect("the canonical path is not absolute?"),
                Url::from_file_path(repo_path.join("targets"))
                    .expect("the canonical path is not absolute?"),
            )
            .expiration_enforcement(exp)
            .load()
            .await
            {
                Ok(repo) => {
                    return Ok(Self {
                        log: log.new(slog::o!("component" => "OmicronRepo")),
                        repo,
                        repo_path,
                    });
                }
                Err(
                    err @ (Error::VerifyMetadata { .. }
                    | Error::VerifyTrustedMetadata { .. }),
                ) if verify_error.is_none() => {
                    verify_error = Some(err.into());
                    continue;
                }
                Err(err) => return Err(err.into()),
            }
        }
        Err(verify_error.unwrap_or_else(|| anyhow!("trust store is empty")))
    }

    /// Loads a repository from the given path.
    ///
    /// This method enforces expirations. To load without expiration enforcement, use
    /// [`Self::load_untrusted_ignore_expiration`].
    pub async fn load_untrusted(
        log: &slog::Logger,
        repo_path: &Utf8Path,
    ) -> Result<Self> {
        Self::load_untrusted_impl(log, repo_path, ExpirationEnforcement::Safe)
            .await
    }

    /// Loads a repository from the given path, ignoring expiration.
    ///
    /// Use cases for this include:
    ///
    /// 1. When you're editing an existing repository and will re-sign it afterwards.
    /// 2. When you're reading a repository that was uploaded out-of-band,
    ///    instead of fetched from a network-accessible repository
    /// 3. In an environment in which time isn't available.
    pub async fn load_untrusted_ignore_expiration(
        log: &slog::Logger,
        repo_path: &Utf8Path,
    ) -> Result<Self> {
        Self::load_untrusted_impl(log, repo_path, ExpirationEnforcement::Unsafe)
            .await
    }

    async fn load_untrusted_impl(
        log: &slog::Logger,
        repo_path: &Utf8Path,
        exp: ExpirationEnforcement,
    ) -> Result<Self> {
        let repo_path = repo_path.canonicalize_utf8()?;
        let root_json = repo_path.join("metadata").join("1.root.json");
        let root = tokio::fs::read(&root_json)
            .await
            .with_context(|| format!("error reading from {root_json}"))?;
        Self::load_impl(log, &repo_path, &[root], exp).await
    }

    /// Returns a canonicalized form of the repository path.
    pub fn repo_path(&self) -> &Utf8Path {
        &self.repo_path
    }

    /// Returns the repository.
    pub fn repo(&self) -> &Repository {
        &self.repo
    }

    /// Reads the artifacts document from the repo.
    pub async fn read_artifacts(&self) -> Result<ArtifactsDocument> {
        let reader = self
            .repo
            .read_target(&ArtifactsDocument::FILE_NAME.try_into()?)
            .await?
            .ok_or_else(|| {
                anyhow!("{} should be present", ArtifactsDocument::FILE_NAME)
            })?;
        let buf_list =
            reader.try_collect::<BufList>().await.with_context(|| {
                format!("error reading from {}", ArtifactsDocument::FILE_NAME)
            })?;
        serde_json::from_reader(buf_list::Cursor::new(&buf_list)).with_context(
            || format!("error deserializing {}", ArtifactsDocument::FILE_NAME),
        )
    }

    /// Archives the repository to the given path as a zip file.
    ///
    /// ## Why zip and not tar?
    ///
    /// The main reason is that zip supports random access to files and tar does
    /// not.
    ///
    /// In principle it should be possible to read the repository out of a zip
    /// file from memory, but we ran into [this
    /// issue](https://github.com/awslabs/tough/pull/563) while implementing it.
    /// Once that is resolved (or we write our own TUF crate) it should be
    /// possible to do that.
    ///
    /// Regardless of this roadblock, we don't want to foreclose that option
    /// forever, so this code uses zip rather than having to deal with a
    /// migration in the future.
    pub fn archive(&self, output_path: &Utf8Path) -> Result<()> {
        let mut builder = ArchiveBuilder::new(output_path.to_owned())?;

        let metadata_dir = self.repo_path.join("metadata");

        // Gather metadata files.
        for entry in metadata_dir.read_dir_utf8().with_context(|| {
            format!("error reading entries from {metadata_dir}")
        })? {
            let entry =
                entry.context("error reading entry from {metadata_dir}")?;
            let file_name = entry.file_name();
            if file_name.ends_with(".root.json")
                || file_name == "timestamp.json"
                || file_name.ends_with(".snapshot.json")
                || file_name.ends_with(".targets.json")
            {
                // This is a valid metadata file.
                builder.write_file(
                    entry.path(),
                    &Utf8Path::new("metadata").join(file_name),
                )?;
            }
        }

        let targets_dir = self.repo_path.join("targets");

        // Gather all targets.
        for (name, target) in self.repo.targets().signed.targets_iter() {
            let target_filename = self.target_filename(target, name);
            let target_path = targets_dir.join(&target_filename);
            slog::trace!(self.log, "adding {} to archive", name.resolved());
            builder.write_file(
                &target_path,
                &Utf8Path::new("targets").join(&target_filename),
            )?;
        }

        builder.finish()?;

        Ok(())
    }

    /// Converts `self` into an `OmicronRepoEditor`, which can be used to perform
    /// modifications to the repository.
    pub async fn into_editor(self) -> Result<OmicronRepoEditor> {
        OmicronRepoEditor::new(self).await
    }

    /// Prepends the target digest to the name if using consistent snapshots. Returns both the
    /// digest and the filename.
    ///
    /// Adapted from tough's source.
    fn target_filename(&self, target: &Target, name: &TargetName) -> String {
        let sha256 = &target.hashes.sha256.clone().into_vec();
        if self.repo.root().signed.consistent_snapshot {
            format!("{}.{}", hex::encode(sha256), name.resolved())
        } else {
            name.resolved().to_owned()
        }
    }
}

/// An [`OmicronRepo`] than can be edited.
///
/// Created by [`OmicronRepo::into_editor`].
pub struct OmicronRepoEditor {
    editor: RepositoryEditor,
    repo_path: Utf8PathBuf,
    artifacts: ArtifactsDocument,

    // Set of `TargetName::resolved()` names for every target that existed when
    // the repo was opened. We use this to ensure we don't overwrite an existing
    // target when adding new artifacts.
    existing_target_names: BTreeSet<String>,
    // Set of (kind, hash) pairs for every artifact and deployment unit known to
    // the repo. Used to ensure (kind, hash) pairs are unique within this repo.
    existing_deployment_units: DeploymentUnitMapBuilder,
}

impl OmicronRepoEditor {
    async fn new(repo: OmicronRepo) -> Result<Self> {
        let artifacts = repo.read_artifacts().await?;
        let artifacts_by_target_name = artifacts
            .artifacts
            .iter()
            .map(|artifact| (artifact.target.as_str(), artifact))
            .collect::<BTreeMap<_, _>>();

        let mut errors = Vec::new();

        // TODO: In the future, it would be nice to extract deployment units
        // from composite artifacts. But that would require parsing each file,
        // and the code for that lives in Omicron under update-common.
        //
        // For now we settle for treating all artifacts as single-unit ones.
        let mut data_builder =
            DeploymentUnitMapBuilder::new(DeploymentUnitScope::Repository);

        let existing_target_names = repo
            .repo
            .targets()
            .signed
            .targets_iter()
            .filter_map(|(name, target)| {
                let target_name = name.resolved().to_string();
                if target_name == ArtifactsDocument::FILE_NAME {
                    // The artifacts document does not refer to itself.
                    return None;
                }

                let hash_bytes = <[u8; 32]>::try_from(
                    target.hashes.sha256.clone().into_vec(),
                )
                .expect("SHA-256 hash should be exactly 32 bytes");
                let hash = ArtifactHash(hash_bytes);

                let Some(artifact) =
                    artifacts_by_target_name.get(target_name.as_str())
                else {
                    errors.push(anyhow!(
                        "artifact `{}` not found in {}",
                        target_name,
                        ArtifactsDocument::FILE_NAME
                    ));
                    return None;
                };

                let Ok(()) = data_builder.insert(DeploymentUnitData {
                    name: artifact.name.to_owned(),
                    version: artifact.version.clone(),
                    kind: artifact.kind.clone(),
                    hash,
                }) else {
                    errors.push(anyhow!(
                        "failed to add deployment unit for artifact `{}`",
                        target_name
                    ));
                    return None;
                };

                Some(target_name)
            })
            .collect::<BTreeSet<_>>();

        // If any errors were found, return them.
        if !errors.is_empty() {
            return Err(merge_anyhow_list(errors));
        }

        let editor = RepositoryEditor::from_repo(
            repo.repo_path
                .join("metadata")
                .join(format!("{}.root.json", repo.repo.root().signed.version)),
            repo.repo,
        )
        .await?;

        Ok(Self {
            editor,
            repo_path: repo.repo_path,
            artifacts,
            existing_target_names,
            existing_deployment_units: DeploymentUnitMapBuilder::new(
                DeploymentUnitScope::Repository,
            ),
        })
    }

    async fn initialize(
        repo_path: Utf8PathBuf,
        root: SignedRole<Root>,
        system_version: Version,
    ) -> Result<Self> {
        let metadata_dir = repo_path.join("metadata");
        let targets_dir = repo_path.join("targets");
        let root_path = metadata_dir
            .join(format!("{}.root.json", root.signed().signed.version));

        fs::create_dir_all(&metadata_dir)?;
        fs::create_dir_all(&targets_dir)?;
        fs::write(&root_path, root.buffer())?;

        let editor = RepositoryEditor::new(&root_path).await?;

        Ok(Self {
            editor,
            repo_path,
            artifacts: ArtifactsDocument::empty(system_version),
            existing_target_names: BTreeSet::new(),
            existing_deployment_units: DeploymentUnitMapBuilder::new(
                DeploymentUnitScope::Repository,
            ),
        })
    }

    /// Adds an artifact to the repository.
    pub fn add_artifact(
        &mut self,
        new_artifact: &AddArtifact,
    ) -> Result<ArtifactHash> {
        let target_name = format!(
            "{}-{}-{}.tar.gz",
            new_artifact.kind(),
            new_artifact.name(),
            new_artifact.version(),
        );

        let mut errors = Vec::new();

        // Make sure we're not overwriting an existing target (either one that
        // existed when we opened the repo, or one that's been added via this
        // method)
        if self.existing_target_names.contains(&target_name) {
            errors.push(anyhow!(
                "a target named {target_name} already exists in the repository",
            ));
        }

        // Start writing the target out to a temporary path, catching errors
        // that might happen.
        let targets_dir = self.repo_path.join("targets");

        let mut file = TargetWriter::new(&targets_dir, target_name.clone())?;
        new_artifact.write_to(&mut file).with_context(|| {
            format!("error writing artifact `{target_name}")
        })?;
        let finished_file = file.finish_write();

        // Make sure we're not adding a new deployment unit with the same
        // kind/hash as an existing one.
        let res = match new_artifact.deployment_units() {
            ArtifactDeploymentUnits::SingleUnit
            | ArtifactDeploymentUnits::Unknown => {
                // For single-unit artifacts, the artifact itself is the
                // deployment unit. For unknown artifacts, we don't know, but
                // treat them as single-unit.
                self.existing_deployment_units.start_insert(
                    DeploymentUnitData {
                        name: new_artifact.name().to_owned(),
                        version: new_artifact.version().clone(),
                        kind: new_artifact.kind().clone(),
                        hash: finished_file.digest(),
                    },
                )
            }
            ArtifactDeploymentUnits::Composite { deployment_units } => {
                // For composite artifacts, merge the deployment units.
                self.existing_deployment_units
                    .start_bulk_insert(deployment_units.clone())
            }
        };
        let new_units = match res {
            Ok(units) => Some(units),
            Err(error) => {
                errors.push(anyhow!(error));
                None
            }
        };

        let version =
            match ArtifactVersion::new(new_artifact.version().to_string()) {
                Ok(version) => Some(version),
                Err(error) => {
                    errors.push(
                        anyhow!(error).context("invalid artifact version"),
                    );
                    None
                }
            };

        if !errors.is_empty() {
            return Err(merge_anyhow_list(errors));
        }

        // ---
        // No errors past this point.
        // ---

        self.existing_target_names.insert(target_name.clone());
        self.artifacts.artifacts.push(Artifact {
            name: new_artifact.name().to_owned(),
            version: version.expect("version is None => errors handled above"),
            kind: new_artifact.kind().clone(),
            target: target_name,
        });
        new_units.expect("new_units is None => errors handled above").commit();

        finished_file.finalize(&mut self.editor)
    }

    /// Consumes self, signing the repository and writing out this repository to disk.
    pub async fn sign_and_finish(
        mut self,
        keys: Vec<Key>,
        expiry: DateTime<Utc>,
    ) -> Result<()> {
        let targets_dir = self.repo_path.join("targets");

        let mut file =
            TargetWriter::new(&targets_dir, ArtifactsDocument::FILE_NAME)?;
        serde_json::to_writer_pretty(&mut file, &self.artifacts)?;
        file.finish_write().finalize(&mut self.editor)?;

        update_versions(&mut self.editor, expiry)?;

        let signed = self
            .editor
            .sign(&crate::key::boxed_keys(keys))
            .await
            .context("error signing keys")?;
        signed
            .write(self.repo_path.join("metadata"))
            .await
            .context("error writing repository")?;
        Ok(())
    }
}

fn update_versions(
    editor: &mut RepositoryEditor,
    expiry: DateTime<Utc>,
) -> Result<()> {
    let version = u64::try_from(Utc::now().timestamp())
        .and_then(NonZeroU64::try_from)
        .expect("bad epoch");
    editor.snapshot_version(version);
    editor.targets_version(version)?;
    editor.timestamp_version(version);
    editor.snapshot_expires(expiry);
    editor.targets_expires(expiry)?;
    editor.timestamp_expires(expiry);
    Ok(())
}

#[cfg(test)]
mod tests {
    use buf_list::BufList;
    use camino_tempfile::Utf8TempDir;
    use chrono::Days;
    use dropshot::test_util::LogContext;
    use dropshot::{ConfigLogging, ConfigLoggingIfExists, ConfigLoggingLevel};

    use crate::assemble::{
        ArtifactDeploymentUnits, ArtifactManifest, OmicronRepoAssembler,
    };
    use crate::{ArchiveExtractor, ArtifactSource};

    use super::*;

    #[tokio::test]
    async fn load_trusted() {
        let log_config = ConfigLogging::File {
            level: ConfigLoggingLevel::Trace,
            path: "UNUSED".into(),
            if_exists: ConfigLoggingIfExists::Fail,
        };
        let logctx = LogContext::new(
            "reject_artifacts_with_the_same_filename",
            &log_config,
        );

        // Generate a "trusted" root and an "untrusted" root.
        let expiry = Utc::now() + Days::new(1);
        let trusted_key = Key::generate_ed25519().unwrap();
        let trusted_root =
            crate::root::new_root(vec![trusted_key.clone()], expiry)
                .await
                .unwrap();
        let untrusted_key = Key::generate_ed25519().unwrap();
        let untrusted_root =
            crate::root::new_root(vec![untrusted_key], expiry).await.unwrap();

        // Generate a repository using the trusted root.
        let tempdir = Utf8TempDir::new().unwrap();
        let archive_path = tempdir.path().join("repo.zip");
        let mut assembler = OmicronRepoAssembler::new(
            &logctx.log,
            ArtifactManifest::new_fake(),
            vec![trusted_key],
            expiry,
            archive_path.clone(),
        );
        assembler.set_root_role(trusted_root.clone());
        assembler.build().await.unwrap();
        // And now that we've created an archive and cleaned up the build
        // directory, immediately unarchive it... this is a bit silly, huh?
        let repo_dir = tempdir.path().join("repo");
        ArchiveExtractor::from_path(&archive_path)
            .unwrap()
            .extract(&repo_dir)
            .unwrap();

        // If the trust store contains the root we generated the repo from, we
        // should successfully load it.
        for trust_store in [
            vec![trusted_root.buffer()],
            vec![trusted_root.buffer(), untrusted_root.buffer()],
            vec![untrusted_root.buffer(), trusted_root.buffer()],
            vec![trusted_root.buffer(), trusted_root.buffer()],
        ] {
            OmicronRepo::load(&logctx.log, &repo_dir, trust_store)
                .await
                .unwrap();
        }
        // If the trust store is empty, we should fail.
        assert_eq!(
            OmicronRepo::load(&logctx.log, &repo_dir, [] as [Vec<u8>; 0])
                .await
                .unwrap_err()
                .to_string(),
            "trust store is empty"
        );
        // If the trust store otherwise does not contain the root we generated
        // the repo from, we should also fail.
        for trust_store in [
            vec![untrusted_root.buffer()],
            vec![untrusted_root.buffer(), untrusted_root.buffer()],
        ] {
            assert_eq!(
                OmicronRepo::load(&logctx.log, &repo_dir, trust_store)
                    .await
                    .unwrap_err()
                    .to_string(),
                "Failed to verify timestamp metadata: \
                Signature threshold of 1 not met for role timestamp \
                (0 valid signatures)"
            )
        }

        logctx.cleanup_successful();
    }

    #[tokio::test]
    async fn reject_artifacts_with_the_same_filename() {
        let log_config = ConfigLogging::File {
            level: ConfigLoggingLevel::Trace,
            path: "UNUSED".into(),
            if_exists: ConfigLoggingIfExists::Fail,
        };
        let logctx = LogContext::new(
            "reject_artifacts_with_the_same_filename",
            &log_config,
        );
        let tempdir = Utf8TempDir::new().unwrap();
        let mut repo = OmicronRepo::initialize(
            &logctx.log,
            tempdir.path(),
            "0.0.0".parse().unwrap(),
            vec![Key::generate_ed25519().unwrap()],
            None,
            Utc::now() + Days::new(1),
        )
        .await
        .unwrap()
        .into_editor()
        .await
        .unwrap();

        // Targets are uniquely identified by their kind/name/version triple;
        // trying to add two artifacts with identical triples should fail.
        let kind = "test-kind";
        let name = "test-artifact-name";
        let version = "1.0.0";

        repo.add_artifact(&AddArtifact::new(
            kind.parse().unwrap(),
            name.to_string(),
            version.parse().unwrap(),
            ArtifactSource::Memory(BufList::from("first")),
            ArtifactDeploymentUnits::Unknown,
        ))
        .unwrap();

        let err = repo
            .add_artifact(&AddArtifact::new(
                kind.parse().unwrap(),
                name.to_string(),
                version.parse().unwrap(),
                ArtifactSource::Memory(BufList::from("second")),
                ArtifactDeploymentUnits::Unknown,
            ))
            .unwrap_err();

        println!("error: {:?}", err);
        let err = err.to_string();

        assert!(err.contains("a target named"));
        assert!(err.contains(kind));
        assert!(err.contains(name));
        assert!(err.contains(version));
        assert!(err.contains("already exists"));

        logctx.cleanup_successful();
    }
}
