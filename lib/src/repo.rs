// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod check;
mod v1;

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use camino::Utf8Path;
use camino::Utf8PathBuf;
use futures_util::Stream;
use futures_util::TryStreamExt;
use rawzip::FileReader;
use semver::Version;
use serde::de::DeserializeOwned;
use slog::Logger;
use slog::warn;
use tokio::sync::Semaphore;
use tokio::sync::TryAcquireError;
use tokio::task::JoinSet;
use tough::TargetName;
use tough::schema::Target;
use tufaceous_artifact::Artifact;
use tufaceous_artifact::ArtifactHash;
use tufaceous_artifact::ArtifactSet;
use tufaceous_artifact::KnownArtifactTags;
use tufaceous_artifact::Metadata;
use tufaceous_artifact::artifact_set::GetError;

use crate::RepositoryLoader;
use crate::error::Error;
use crate::error::ErrorKind;
pub use crate::repo::check::CheckProblem;
use crate::schema::ArtifactSchema;
use crate::schema::ArtifactSetSchema;

pub type TargetStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, Error>> + Send + Sync + 'static>>;

/// A loaded TUF repository.
#[derive(Debug, Clone)]
pub struct Repository {
    log: Logger,
    inner: tough::Repository,
    system_version: Version,
    trust_root: Vec<u8>,
    artifacts: ArtifactSet,
    artifact_data: BTreeMap<Artifact, ArtifactData>,
    metadata: BTreeMap<String, String>,

    // These are set directly by the ZIP archive convenience methods in the
    // loader module.
    // TODO after v2 merge: Move the loader module under this repo module so
    // that this doesn't need to be pub(crate).
    pub(crate) archive_path: Option<Utf8PathBuf>,
    pub(crate) archive_sha256: Option<[u8; 32]>,
}

impl Repository {
    pub fn loader() -> RepositoryLoader {
        RepositoryLoader::new()
    }

    /// Generate and load a fake repository.
    ///
    /// This is shorthand for:
    ///
    /// ```rust
    /// # tokio_test::block_on(async {
    /// # let system_version = const { semver::Version::new(1, 0, 0) };
    /// # let log = slog::Logger::root(slog::Discard, slog::o!());
    /// # let log = &log;
    /// let zip = tufaceous::edit::RepositoryEditor::fake(system_version)?
    ///     .finish()
    ///     .await?
    ///     .generate_root()
    ///     .sign()
    ///     .await?
    ///     .write_zip(Vec::new(), chrono::Utc::now())
    ///     .await?;
    /// # Ok::<_, tufaceous::error::Error>(
    /// tufaceous::RepositoryLoader::new()
    ///     .trust_store_behavior(tufaceous::TrustStoreBehavior::UnsafeBlindFaith)
    ///     .load_zip_buffer(zip, log)
    ///     .await?
    /// # )
    /// # }).unwrap();
    /// ```
    pub async fn fake(
        system_version: Version,
        log: &Logger,
    ) -> Result<Self, Error> {
        let zip = crate::edit::RepositoryEditor::fake(system_version)?
            .finish()
            .await?
            .generate_root()
            .sign()
            .await?
            .write_zip(Vec::new(), chrono::Utc::now())
            .await?;
        RepositoryLoader::new()
            .trust_store_behavior(crate::TrustStoreBehavior::UnsafeBlindFaith)
            .load_zip_buffer(zip, log)
            .await
    }

    pub(crate) async fn from_loaded(
        repo: tough::Repository,
        log: &Logger,
        trust_root: Vec<u8>,
        v1_compatibility: bool,
    ) -> Result<Self, Error> {
        let Some(ArtifactSetSchema { system_version, artifacts, metadata }) =
            read_target_json(&repo, ArtifactSetSchema::TARGET_NAME).await?
        else {
            if v1_compatibility
                && let Some(partial) = v1::from_loaded(&repo, log).await?
            {
                return Ok(Repository {
                    log: log.clone(),
                    inner: repo,
                    trust_root,
                    system_version: partial.system_version,
                    artifacts: partial.artifacts,
                    artifact_data: partial.artifact_data,
                    metadata: BTreeMap::new(),
                    archive_path: None,
                    archive_sha256: None,
                });
            }

            return Err(ErrorKind::TargetNotFound {
                target_name: ArtifactSetSchema::TARGET_NAME.to_owned(),
            }
            .into());
        };

        let (artifacts, artifact_data) = artifacts
            .into_iter()
            .filter_map(|ArtifactSchema { target_name, version, tags }| {
                let (hash, length) =
                    target_meta_skip(&repo, log, &target_name)?;
                let artifact = Artifact { version, tags, hash, length };
                Some((
                    artifact.clone(),
                    (artifact, ArtifactData::Target { target_name }),
                ))
            })
            .collect();
        Ok(Repository {
            log: log.clone(),
            inner: repo,
            trust_root,
            system_version,
            artifacts,
            artifact_data,
            metadata,
            archive_path: None,
            archive_sha256: None,
        })
    }

    pub fn system_version(&self) -> &Version {
        &self.system_version
    }

    pub fn trust_root(&self) -> &[u8] {
        &self.trust_root
    }

    /// Returns the path to the loaded archive, if there is one.
    ///
    /// Set when [`RepositoryLoader::load_zip_file`] or
    /// [`RepositoryLoader::load_zip_path`] are used.
    pub fn archive_path(&self) -> Option<&Utf8Path> {
        self.archive_path.as_deref()
    }

    /// Returns the SHA256 digest of the loaded archive, if there is one.
    ///
    /// Set when [`RepositoryLoader::compute_archive_sha256`] is set to `true`
    /// and one of the archive loading methods is used.
    pub fn archive_sha256(&self) -> Option<&[u8; 32]> {
        self.archive_sha256.as_ref()
    }

    pub fn targets(&self) -> &HashMap<TargetName, Target> {
        &self.inner.targets().signed.targets
    }

    pub fn artifacts(&self) -> &ArtifactSet {
        &self.artifacts
    }

    /// Returns an [`ArtifactSchema`] for the artifacts in the repository.
    ///
    /// This is used by [`crate::edit::RepositoryEditor::import_repo`].
    ///
    /// # Errors
    ///
    /// If this was a v1 repository, returns an error; we don't have a valid
    /// target name for unpacked artifacts.
    pub(crate) fn to_artifact_schema(
        &self,
    ) -> Result<Vec<ArtifactSchema>, Error> {
        self.artifact_data
            .iter()
            .map(|(artifact, data)| match data {
                ArtifactData::Target { target_name } => Ok(ArtifactSchema {
                    target_name: target_name.clone(),
                    version: artifact.version.clone(),
                    tags: artifact.tags.clone(),
                }),
                ArtifactData::V1Unpacked { .. } => {
                    Err(ErrorKind::ImportV1Repo.into())
                }
            })
            .collect()
    }

    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }

    pub fn structured_metadata(&self) -> Option<Metadata> {
        Metadata::from_map(self.metadata.clone()).ok()
    }

    pub async fn read_artifact(
        &self,
        artifact: &Artifact,
    ) -> Result<TargetStream, Error> {
        let data = self
            .artifact_data
            .get(artifact)
            .ok_or_else(|| ErrorKind::ArtifactNotFound(artifact.clone()))?;
        match data {
            ArtifactData::Target { target_name } => {
                self.read_target(target_name).await
            }
            ArtifactData::V1Unpacked {
                file,
                original_target_name,
                inner_path,
            } => {
                let unpacked = v1::UnpackedArtifact {
                    file: file.clone(),
                    hash: artifact.hash,
                    length: artifact.length,
                };
                Ok(Box::pin(unpacked.stream(
                    self.log.clone(),
                    original_target_name.clone(),
                    inner_path.clone(),
                )))
            }
        }
    }

    /// Read a target from the underlying TUF repository by its target name.
    ///
    /// If you have an [`Artifact`], use [`Self::read_artifact`].
    pub async fn read_target(
        &self,
        target_name: &str,
    ) -> Result<TargetStream, Error> {
        if let Some(stream) = read_target(&self.inner, target_name).await? {
            Ok(Box::pin(stream))
        } else {
            Err(ErrorKind::TargetNotFound {
                target_name: target_name.to_owned(),
            }
            .into())
        }
    }

    /// Returns an [`ArtifactHandle`] for the one (and only one) artifact
    /// matching `tags` that can be used to stream the artifact.
    ///
    /// An artifact handle simply clones `artifact` and `self` and keeps them
    /// together in a struct as a convenience. The repository must be wrapped in
    /// [`Arc`] to call this method.
    ///
    /// # Errors
    ///
    /// Returns an error if there is not exactly one artifact matching `tags`.
    pub fn get_handle(
        self: &Arc<Self>,
        tags: &KnownArtifactTags,
    ) -> Result<ArtifactHandle, GetError> {
        let artifact = self.artifacts.get_only(tags)?.clone();
        Ok(ArtifactHandle { artifact, repo: Arc::clone(self) })
    }

    /// Returns an iterator of [`ArtifactHandle`]s for every artifact
    /// in the repository.
    ///
    /// An artifact handle simply clones `artifact` and `self` and keeps them
    /// together in a struct as a convenience. The repository must be wrapped in
    /// [`Arc`] to call this method.
    pub fn handles(self: &Arc<Self>) -> impl Iterator<Item = ArtifactHandle> {
        self.artifacts
            .iter()
            .cloned()
            .map(|artifact| ArtifactHandle { artifact, repo: Arc::clone(self) })
    }

    /// Reads all targets in the repository and verifies they have the correct
    /// length and checksum.
    ///
    /// The repository must be wrapped in [`Arc`] to call this method.
    ///
    /// This method is *not* necessary to safely read the repository. All
    /// streams returned from [`Repository::read_target`] and read completely
    /// are verified to have the same correct length and checksum.
    ///
    /// However, this verification is useful to complete before using contents
    /// for any operations if you have the entire repository available locally.
    /// In the past, Tufaceous archives were used by completely unpacking the
    /// archive, which verified the contents against the CRC-32 checksums in the
    /// ZIP archive; this caught binaries that were corrupted in transit between
    /// CI and destination hardware.
    ///
    /// `parallelism` controls how many targets are read at a time.
    #[expect(clippy::missing_panics_doc)]
    pub async fn verify_targets(
        &self,
        parallelism: usize,
    ) -> Result<(), Error> {
        // This is a reimplementation of `parallel-task-set` from Omicron,
        // and could potentially be replaced with that if it's published to
        // crates.io.
        let semaphore = Arc::new(Semaphore::new(parallelism.max(1)));
        let mut set: JoinSet<Result<(), Error>> = JoinSet::new();

        for target_name in self.targets().keys() {
            let target = target_name.raw().to_owned();
            let permit = match Arc::clone(&semaphore).try_acquire_owned() {
                Ok(permit) => permit,
                Err(TryAcquireError::Closed) => {
                    unreachable!("we never close the semaphore")
                }
                Err(TryAcquireError::NoPermits) => {
                    if let Some(result) = set.join_next().await {
                        () = result??;
                    }
                    Arc::clone(&semaphore)
                        .acquire_owned()
                        .await
                        .expect("we never close the semaphore")
                }
            };
            let mut stream = self.read_target(&target).await?;
            set.spawn(async move {
                let _permit = permit;
                // Read the stream to the end. There's no need to do anything
                // with the data; the underlying stream performs verification.
                while stream.try_next().await?.is_some() {}
                Ok(())
            });
        }

        while let Some(result) = set.join_next().await {
            () = result??;
        }

        Ok(())
    }
}

/// While we have v1 compatibility, artifacts might come from the underlying
/// `tough::Repository` or from an unpacked file on disk. When we drop all v1
/// compatibility code we can remove this indirection.
#[derive(Debug, Clone)]
enum ArtifactData {
    /// The artifact is read from the underlying `tough::Repository`.
    Target { target_name: String },
    /// The artifact was unpacked from a composite artifact in a v1 repository,
    /// and is read from a temporary file on disk.
    V1Unpacked {
        file: Arc<FileReader>,
        original_target_name: String,
        inner_path: Utf8PathBuf,
    },
}

impl ArtifactData {
    fn original_target_name(&self) -> &str {
        match self {
            ArtifactData::Target { target_name } => target_name,
            ArtifactData::V1Unpacked { original_target_name, .. } => {
                original_target_name
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArtifactHandle {
    artifact: Artifact,
    repo: Arc<Repository>,
}

impl ArtifactHandle {
    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }

    pub fn into_artifact(self) -> Artifact {
        self.artifact
    }

    pub async fn stream(&self) -> Result<TargetStream, Error> {
        self.repo.read_artifact(&self.artifact).await
    }
}

async fn read_target(
    repo: &tough::Repository,
    target: &str,
) -> Result<Option<impl Stream<Item = Result<Bytes, Error>> + 'static>, Error> {
    let target_name = target.parse()?;
    // Ensure the target is in the top-level targets.json role and not a
    // delegated target; we don't permit the use of delegated targets in
    // Tufaceous currently.
    if !repo.targets().signed.targets.contains_key(&target_name) {
        return Ok(None);
    }
    Ok(repo
        .read_target(&target_name)
        .await?
        .map(TryStreamExt::err_into::<Error>))
}

async fn read_target_vec(
    repo: &tough::Repository,
    target: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let Some(stream) = read_target(repo, target).await? else {
        return Ok(None);
    };
    stream.map_ok(Vec::from).try_concat().await.map(Some)
}

async fn read_target_json<T: DeserializeOwned>(
    repo: &tough::Repository,
    target: &str,
) -> Result<Option<T>, Error> {
    let Some(vec) = read_target_vec(repo, target).await? else {
        return Ok(None);
    };
    serde_json::from_slice(&vec).map_err(|source| {
        ErrorKind::ParseTargetJson { source, target: target.into() }.into()
    })
}

fn target_meta_inner(
    target: &Target,
) -> Result<(ArtifactHash, u64), InvalidTargetError> {
    Ok((
        ArtifactHash(target.hashes.sha256.as_ref().try_into().map_err(
            |_| InvalidTargetError::ChecksumLength {
                sha256: target.hashes.sha256.to_vec(),
            },
        )?),
        target.length,
    ))
}

fn target_meta(
    repo: &tough::Repository,
    target_name: &str,
) -> Result<(ArtifactHash, u64), InvalidTargetError> {
    let name = TargetName::new(target_name)
        .map_err(|_| InvalidTargetError::NameRejected)?;
    let Some(target) = repo.targets().signed.targets.get(&name) else {
        return Err(InvalidTargetError::NotFound);
    };
    target_meta_inner(target)
}

fn target_meta_skip(
    repo: &tough::Repository,
    log: &Logger,
    target_name: &str,
) -> Option<(ArtifactHash, u64)> {
    target_meta(repo, target_name)
        .inspect_err(|error| {
            warn!(
                log,
                "skipping artifact";
                "target_name" => &target_name,
                "error" => crate::util::error_chain(&error),
            );
        })
        .ok()
}

#[derive(Debug, thiserror::Error)]
enum InvalidTargetError {
    #[error("target name rejected by tough")]
    NameRejected,
    #[error("target not found")]
    NotFound,
    #[error("incorrect sha256 length for {:?}", hex::encode(.sha256))]
    ChecksumLength { sha256: Vec<u8> },
}
