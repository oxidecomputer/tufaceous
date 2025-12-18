// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::Deserialize;
use serde::Serialize;

use crate::ArtifactHash;

/// Artifact-specific information used by installinator.
///
/// This document is treated as an opaque blob by Wicketd and Nexus, since
/// we'd like previous versions of those services to be able to process newer
/// versions of this document.
///
/// There are no backwards compatibility constraints for this document. The
/// version of installinator that processes this document is the same as the
/// version of tufaceous that creates it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InstallinatorDocument {
    pub artifacts: Vec<InstallinatorArtifact>,
}

/// Describes an artifact available to installinator.
///
/// The fields here match [`Artifact`](crate::Artifact).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InstallinatorArtifact {
    /// A file name; not necessarily the target name.
    pub name: String,
    pub kind: InstallinatorArtifactKind,
    pub sha256: ArtifactHash,
}

/// The artifact kind for an installinator artifact.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallinatorArtifactKind {
    /// A measurement corpus.
    MeasurementCorpus,
    /// The host phase 2 artifact.
    HostPhase2,
    /// A control plane zone artifact.
    Zone { name: String },
}
