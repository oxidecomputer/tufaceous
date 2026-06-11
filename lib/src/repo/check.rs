// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;

use daft::Diffable;
use futures_util::TryStreamExt;
use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::DisplayTags;
use tufaceous_artifact::InstallinatorDocument;
use tufaceous_artifact::KnownArtifactTags;
use tufaceous_artifact::OsBoard;
use tufaceous_artifact::OsPhase1Tags;
use tufaceous_artifact::OsPhase2Tags;
use tufaceous_artifact::OsVariant;
use tufaceous_artifact::artifact_set::GetError;

use crate::Repository;
use crate::repo::ArtifactData;
use crate::repo::InvalidTargetError;
use crate::repo::target_meta;
use crate::repo::target_meta_inner;

impl Repository {
    /// Check the repository for consistency and other problems.
    ///
    /// # ⚠️ Causality Hazard ⚠️
    ///
    /// The definition of a well-formed repository is subject to change. This
    /// must **not** be used for repositories that may have been created by
    /// another version of Tufaceous, such as when the control plane decides to
    /// accept a repository.
    #[allow(clippy::too_many_lines)]
    pub async fn check_problems(&self) -> Vec<CheckProblem> {
        let mut problems = Vec::new();

        for (target_name, target) in self.targets() {
            if target_name.raw() != target_name.resolved() {
                problems.push(CheckProblem::BadTargetName {
                    target_name: target_name.raw().to_owned(),
                });
            }
            if let Err(error) = target_meta_inner(target) {
                problems.push(CheckProblem::from_invalid_target(
                    error,
                    target_name.raw().to_owned(),
                ));
            }
        }

        for (artifact, data) in &self.artifact_data {
            if let ArtifactData::Target { target_name } = data
                && let Err(error) = target_meta(&self.inner, target_name)
            {
                problems.push(CheckProblem::from_invalid_target(
                    error,
                    target_name.to_owned(),
                ));
            }
            // Check that no artifact contains unknown tags.
            if artifact.known_tags().is_none() {
                problems.push(CheckProblem::UnknownTags {
                    target_name: data.original_target_name().to_owned(),
                    tags: artifact.tags.clone(),
                });
            }
        }

        match self
            .structured_metadata()
            .and_then(|structured_metadata| structured_metadata.to_map().ok())
        {
            Some(metadata) => {
                if self.metadata() != &metadata {
                    let diff = self.metadata().diff(&metadata);
                    for (key, leaf) in diff.modified() {
                        problems.push(CheckProblem::UnexpectedMetadataDiff {
                            key: key.clone(),
                            old_value: Some(leaf.before.clone()),
                            new_value: leaf.after.clone(),
                        });
                    }
                    for (key, value) in diff.added {
                        problems.push(CheckProblem::UnexpectedMetadataDiff {
                            key: key.clone(),
                            old_value: None,
                            new_value: value.clone(),
                        });
                    }
                    for (key, _) in diff.removed {
                        problems.push(CheckProblem::UnknownMetadataKey(
                            key.clone(),
                        ));
                    }
                }
            }
            None => {
                problems.push(CheckProblem::UnknownMetadata(
                    self.metadata().clone(),
                ));
            }
        }

        // For all tags we expect to see a single artifact, except for
        // MeasurementCorpus.
        for (tags, iter) in self.artifacts().known() {
            if iter.len() > 1 && !tags.allow_multiple_artifacts() {
                problems.push(CheckProblem::MultipleArtifacts(tags.clone()));
            }
        }

        // We expect to see artifacts matching these tags for Installinator
        // to work.
        let mut expected = vec![KnownArtifactTags::InstallinatorDocument];
        for os_variant in [OsVariant::Host, OsVariant::Recovery] {
            for os_board in [OsBoard::COSMO, OsBoard::GIMLET] {
                expected.push(KnownArtifactTags::OsPhase1(OsPhase1Tags {
                    os_board,
                    os_variant,
                }));
            }
            expected
                .push(KnownArtifactTags::OsPhase2(OsPhase2Tags { os_variant }));
        }
        for tags in expected {
            if matches!(
                self.artifacts().get_only(&tags),
                Err(GetError::NotFound)
            ) {
                problems.push(CheckProblem::MissingArtifact(tags));
            }
        }

        if let Ok(artifact) =
            self.artifacts().get_only(&KnownArtifactTags::InstallinatorDocument)
            && let Ok(stream) = self.read_artifact(artifact).await
            && let Ok(bytes) = stream.map_ok(Vec::from).try_concat().await
            && let Ok(doc) = serde_json::from_slice::<InstallinatorDocument>(
                &bytes,
            )
            .map_err(|source| {
                problems.push(CheckProblem::DeserializeInstallinator(source));
            })
            && doc.system_version.as_str() != self.system_version().to_string()
        {
            problems.push(CheckProblem::InstallinatorVersion {
                doc_version: doc.system_version.clone(),
                system_version: self.system_version().clone(),
            });
        }

        problems
    }
}

/// Possible problems found by [`Repository::check_problems`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CheckProblem {
    /// The Installinator document could not be parsed.
    #[error("failed to deserialize Installinator document")]
    DeserializeInstallinator(#[source] serde_json::Error),

    /// The Installinator document has the wrong system version.
    #[error(
        "Installinator document has version {doc_version} \
        but the system version is {system_version}"
    )]
    InstallinatorVersion {
        doc_version: ArtifactVersion,
        system_version: semver::Version,
    },

    /// An artifact matching these tags was not found.
    #[error("no artifact matching {0}")]
    MissingArtifact(KnownArtifactTags),

    /// An artifact's target name is not in the repository.
    #[error(
        "artifact with target name {target_name} listed but not present \
        in repository"
    )]
    MissingTarget { target_name: String },

    /// A target name in the repository is not well-formed.
    #[error("target name {target_name} is not well-formed")]
    BadTargetName { target_name: String },

    /// A SHA-256 checksum in the TUF repository metadata has an invalid length.
    #[error(
        "target {target_name} has SHA-256 checksum {} with invalid length",
        hex::encode(.sha256)
    )]
    TargetHashLengthMismatch { target_name: String, sha256: Vec<u8> },

    /// Multiple artifacts for these tags were not expected.
    #[error("multiple artifacts found matching {0}")]
    MultipleArtifacts(KnownArtifactTags),

    /// The repository metadata is unexpectedly different from the parsed
    /// structured metadata.
    #[error(
        "unexpected diff in structured metadata: \
        {key}={old_value:?}->{new_value:?}"
    )]
    UnexpectedMetadataDiff {
        key: String,
        old_value: Option<String>,
        new_value: String,
    },

    /// The repository metadata cannot be parsed.
    #[error("couldn't parse metadata {0:?}")]
    UnknownMetadata(BTreeMap<String, String>),

    /// The repository metadata contains an unknown key.
    #[error("unknown metadata key {0:?}")]
    UnknownMetadataKey(String),

    /// An artifact has unknown tags.
    #[error(
        "artifact {target_name} has unknown tags {}",
        DisplayTags::from(.tags)
    )]
    UnknownTags { target_name: String, tags: BTreeMap<String, String> },
}

impl CheckProblem {
    fn from_invalid_target(
        source: InvalidTargetError,
        target_name: String,
    ) -> Self {
        match source {
            InvalidTargetError::NameRejected => {
                Self::BadTargetName { target_name }
            }
            InvalidTargetError::NotFound => Self::MissingTarget { target_name },
            InvalidTargetError::ChecksumLength { sha256 } => {
                Self::TargetHashLengthMismatch { target_name, sha256 }
            }
        }
    }
}
