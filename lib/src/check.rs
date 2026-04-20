// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;

use daft::Diffable;
use tufaceous_artifact::DisplayTags;
use tufaceous_artifact::KnownArtifactTags;
use tufaceous_artifact::OsBoard;
use tufaceous_artifact::OsPhase1Tags;
use tufaceous_artifact::OsPhase2Tags;
use tufaceous_artifact::OsVariant;
use tufaceous_artifact::artifact_set::GetError;

use crate::Repository;

impl Repository {
    /// Check the repository for consistency and other problems.
    ///
    /// This must *not* be used to determine whether to accept a repository by
    /// the control plane; it assumes that the current version of Tufaceous is
    /// the same one that was used to generate the repository.
    pub fn check_problems(&self) -> Vec<CheckProblem> {
        let mut problems = Vec::new();

        for artifact in self.artifacts() {
            // Check that all targets listed in `artifacts-v2.json` actually
            // exist in the repository.
            if !self.contains_target(&artifact.target_name) {
                problems.push(CheckProblem::MissingTarget {
                    target_name: artifact.target_name.clone(),
                });
            }
            // Check that no artifact contains unknown tags.
            if artifact.known_tags().is_none() {
                problems.push(CheckProblem::UnknownTags {
                    target_name: artifact.target_name.clone(),
                    tags: artifact.tags.clone(),
                });
            }
        }

        match self.structured_metadata() {
            Some(structured_metadata) => {
                // Serialize the metadata back to a mapping and verify there
                // are no unexpected changes.
                let map = structured_metadata.to_map();
                if self.metadata() != &map {
                    let diff = self.metadata().diff(&map);
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
            if !matches!(tags, KnownArtifactTags::MeasurementCorpus)
                && iter.len() > 1
            {
                problems.push(CheckProblem::MultipleArtifacts(tags.clone()));
            }
        }

        // We expect to see artifacts matching these tags for Installinator
        // to work.
        let mut expected = vec![KnownArtifactTags::InstallinatorDocument];
        for os_variant in [OsVariant::Host, OsVariant::Recovery] {
            for os_board in [OsBoard::Cosmo, OsBoard::Gimlet] {
                expected.push(KnownArtifactTags::OsPhase1(OsPhase1Tags {
                    os_board,
                    os_variant,
                }));
            }
            expected
                .push(KnownArtifactTags::OsPhase2(OsPhase2Tags { os_variant }));
        }
        for tags in expected {
            if matches!(self.artifacts().get(&tags), Err(GetError::NotFound)) {
                problems.push(CheckProblem::MissingArtifact(tags));
            }
        }

        problems
    }
}

/// Possible problems found by [`Repository::check_problems`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CheckProblem {
    /// An artifact matching these tags was not found.
    #[error("no artifact matching {}", .0.display())]
    MissingArtifact(KnownArtifactTags),

    /// An artifact's target name is not in the repository.
    #[error(
        "artifact with target name {target_name} listed but not present \
        in repository"
    )]
    MissingTarget { target_name: String },

    /// Multiple artifacts for these tags were not expected.
    #[error("multiple artifacts found matching {}", .0.display())]
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
