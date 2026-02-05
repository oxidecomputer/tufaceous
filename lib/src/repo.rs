// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
use semver::Version;
use serde::de::DeserializeOwned;
use slog::Logger;
use slog::warn;
use tokio::sync::Semaphore;
use tokio::sync::TryAcquireError;
use tokio::task::JoinSet;
use tough::TargetName;
use tough::schema::Hashes;
use tough::schema::Target;
use tufaceous_artifact::Artifact;
use tufaceous_artifact::ArtifactHash;
use tufaceous_artifact::Artifacts;
use tufaceous_artifact::GetError;
use tufaceous_artifact::KnownArtifactTags;

use crate::RepositoryLoader;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::schema::ArtifactSchema;
use crate::schema::ArtifactsSchema;

pub type TargetStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, Error>> + Send + Sync + 'static>>;

/// A loaded TUF repository.
#[derive(Debug, Clone)]
pub struct Repository {
    inner: tough::Repository,
    system_version: Version,
    trust_root: Vec<u8>,
    pub(crate) archive_path: Option<Utf8PathBuf>,
    pub(crate) archive_sha256: Option<[u8; 32]>,
    artifacts: Artifacts,
    metadata: BTreeMap<String, String>,
    v1_unpacked: Option<v1::Unpacked>,
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
        archive_path: Option<Utf8PathBuf>,
        archive_sha256: Option<[u8; 32]>,
        v1_compatibility: bool,
    ) -> Result<Self, Error> {
        let Some(ArtifactsSchema { system_version, artifacts, metadata }) =
            read_target_json(&repo, ArtifactsSchema::TARGET_NAME).await?
        else {
            if v1_compatibility
                && let Some((system_version, artifacts, v1_unpacked)) =
                    v1::from_loaded(&repo, log).await?
            {
                return Ok(Repository {
                    inner: repo,
                    trust_root,
                    archive_path,
                    archive_sha256,
                    system_version,
                    artifacts,
                    metadata: BTreeMap::new(),
                    v1_unpacked: Some(v1_unpacked),
                });
            }

            return Err(ErrorKind::TargetNotFound {
                target_name: ArtifactsSchema::TARGET_NAME.to_owned(),
            }
            .into());
        };

        let artifacts = artifacts
            .into_iter()
            .filter_map(|ArtifactSchema { target_name, version, tags }| {
                let (hash, length) = sha256_length(&repo, log, &target_name)?;
                Some(Artifact { target_name, version, tags, hash, length })
            })
            .collect();
        Ok(Repository {
            inner: repo,
            trust_root,
            archive_path,
            archive_sha256,
            system_version,
            artifacts,
            metadata,
            v1_unpacked: None,
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

    pub fn artifacts(&self) -> &Artifacts {
        &self.artifacts
    }

    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }

    pub fn is_v1(&self) -> bool {
        self.v1_unpacked.is_some()
    }

    pub async fn read_target(
        &self,
        target: &str,
    ) -> Result<TargetStream, Error> {
        if let Some(stream) = read_target(&self.inner, target).await? {
            return Ok(Box::pin(stream));
        }

        if let Some(unpacked) = &self.v1_unpacked
            && let Some(entry) = unpacked.entries.get(target).cloned()
        {
            return Ok(Box::pin(entry.stream()));
        }

        Err(ErrorKind::TargetNotFound { target_name: target.to_owned() }.into())
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
        tags: KnownArtifactTags,
    ) -> Result<ArtifactHandle, GetError> {
        let artifact = self.artifacts.get(tags)?.clone();
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
                        result??;
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
            result??;
        }

        Ok(())
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
        self.repo.read_target(&self.artifact.target_name).await
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

fn sha256_length(
    repo: &tough::Repository,
    log: &Logger,
    target_name: &str,
) -> Option<(ArtifactHash, u64)> {
    let parsed_name = TargetName::new(target_name)
        .inspect_err(|error| {
            warn!(
                log,
                "skipping artifact";
                "target_name" => &target_name,
                "error" => error.to_string(),
            );
        })
        .ok()?;
    let Some(target) = repo.targets().signed.targets.get(&parsed_name) else {
        warn!(
            log,
            "skipping artifact";
            "target_name" => &target_name,
            "error" => "target not found",
        );
        return None;
    };
    let Hashes { sha256, .. } = &target.hashes;
    let sha256 = sha256
        .as_ref()
        .try_into()
        .inspect_err(|_| {
            warn!(
                log,
                "skipping artifact";
                "target_name" => &target_name,
                "error" => "incorrect checksum length",
                "sha256" => hex::encode(sha256),
            );
        })
        .ok()?;
    Some((sha256, target.length))
}
