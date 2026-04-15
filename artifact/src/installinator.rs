// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;

use serde::Deserialize;
use serde::Serialize;

use crate::ArtifactHash;
use crate::ArtifactVersion;

/// Artifact-specific information used by Installinator.
///
/// This document is treated as an opaque blob by Wicketd and Nexus, since
/// we'd like previous versions of those services to be able to process newer
/// versions of this document.
///
/// There are no backwards compatibility constraints for this document. The
/// version of Installinator that processes this document is the same as the
/// version of Tufaceous that creates it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InstallinatorDocument {
    /// The system version of the repository this document is associated with.
    pub system_version: ArtifactVersion,
    /// The list of Installinator artifacts.
    pub artifacts: BTreeSet<InstallinatorArtifact>,
}

impl InstallinatorDocument {
    /// Creates an Installinator document with the provided system version and
    /// an empty list of artifacts.
    pub fn empty(system_version: ArtifactVersion) -> Self {
        Self { system_version, artifacts: BTreeSet::new() }
    }
}

/// Describes an artifact available to Installinator.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize,
)]
pub struct InstallinatorArtifact {
    /// The artifact kind.
    #[serde(flatten)]
    pub kind: InstallinatorArtifactKind,
    /// The SHA256 hash of the artifact.
    pub hash: ArtifactHash,
    /// A file name without directory separators; not necessarily the target
    /// name.
    // This alias is present for backwards compatibility with Tufaceous v1
    // repositories uploaded to older versions of Wicket that are still using
    // Tufaceous v1. This alias can be removed when the transition is complete.
    #[serde(alias = "name")]
    pub file_name: String,
}

/// The artifact kind for an Installinator artifact.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize,
)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InstallinatorArtifactKind {
    /// The host phase 2 artifact.
    HostPhase2,
    /// A measurement corpus.
    MeasurementCorpus,
    /// A control plane zone artifact.
    Zone {
        /// The zone name, as self-identified in the tarball's `oxide.json`
        /// file. This may differ from the file name.
        zone_name: String,
    },
    /// A tarball of control plane zones. Used for backwards compatibility
    /// only.
    ///
    /// This variant is present for backwards compatibility with Tufaceous
    /// v1 repositories uploaded to older versions of Wicket that are still
    /// using Tufaceous v1. This variant can be removed when the transition
    /// is complete.
    ControlPlane,
}
