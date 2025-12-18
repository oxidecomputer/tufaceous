// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod v1;

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::pin::Pin;

use bytes::Bytes;
use futures_util::Stream;
use futures_util::TryStreamExt;
use semver::Version;
use serde::de::DeserializeOwned;
use slog::Logger;
use slog::warn;
use tough::TargetName;
use tough::schema::Hashes;
use tough::schema::Target;
use tufaceous_artifact::Artifact;
use tufaceous_artifact::ArtifactHash;
use tufaceous_artifact::Artifacts;

use crate::RepositoryLoader;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::schema::ArtifactSchema;
use crate::schema::ArtifactsSchema;

/// A loaded TUF repository.
#[derive(Debug, Clone)]
pub struct Repository {
    inner: tough::Repository,
    system_version: Version,
    trust_root: Vec<u8>,
    artifacts: Artifacts,
    metadata: BTreeMap<String, serde_json::Value>,
    v1_unpacked: Option<v1::Unpacked>,
}

impl Repository {
    pub fn loader() -> RepositoryLoader {
        RepositoryLoader::new()
    }

    pub(crate) async fn from_loaded(
        repo: tough::Repository,
        log: &Logger,
        trust_root: Vec<u8>,
        v1_compatibility: bool,
    ) -> Result<Self, Error> {
        let Some(ArtifactsSchema { system_version, artifacts, metadata }) =
            read_target_json(&repo, ArtifactsSchema::TARGET_NAME).await?
        else {
            if v1_compatibility
                && let Some(repo) =
                    v1::from_loaded(repo, log, trust_root).await?
            {
                return Ok(repo);
            }

            return Err(ErrorKind::TargetNotFound {
                target_name: ArtifactsSchema::TARGET_NAME.to_owned(),
            }
            .into());
        };

        let artifacts = artifacts
            .into_iter()
            .filter_map(|ArtifactSchema { target_name, version, tags }| {
                let (sha256, length) = sha256_length(&repo, log, &target_name)?;
                Some(Artifact { target_name, version, tags, sha256, length })
            })
            .collect();
        Ok(Repository {
            inner: repo,
            trust_root,
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

    pub fn targets(&self) -> &HashMap<TargetName, Target> {
        &self.inner.targets().signed.targets
    }

    pub fn artifacts(&self) -> &Artifacts {
        &self.artifacts
    }

    pub fn metadata(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.metadata
    }

    pub fn is_v1(&self) -> bool {
        self.v1_unpacked.is_some()
    }

    pub async fn read_target<'a>(
        &'a self,
        target: &str,
    ) -> Result<impl Stream<Item = Result<Bytes, Error>> + use<'a>, Error> {
        if let Some(stream) = read_target(&self.inner, target).await? {
            return Ok(Box::pin(stream)
                as Pin<Box<dyn Stream<Item = Result<Bytes, Error>>>>);
        }

        if let Some(unpacked) = &self.v1_unpacked
            && let Some(entry) = unpacked.entries.get(target)
        {
            return Ok(Box::pin(entry.stream()));
        }

        Err(ErrorKind::TargetNotFound { target_name: target.to_owned() }.into())
    }
}

async fn read_target<'a>(
    repo: &'a tough::Repository,
    target: &str,
) -> Result<Option<impl Stream<Item = Result<Bytes, Error>> + use<'a>>, Error> {
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
    let Some(mut stream) = read_target(repo, target).await? else {
        return Ok(None);
    };
    let mut buf = Vec::new();
    while let Some(item) = stream.try_next().await? {
        buf.extend_from_slice(item.as_ref());
    }
    Ok(Some(buf))
}

async fn read_target_json<T: DeserializeOwned>(
    repo: &tough::Repository,
    target: &str,
) -> Result<Option<T>, Error> {
    let Some(vec) = read_target_vec(repo, target).await? else {
        return Ok(None);
    };
    Ok(serde_json::from_slice(&vec).map_err(|source| {
        ErrorKind::ParseTargetJson { source, target: target.into() }
    })?)
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
