// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::ArtifactHash;

/// Artifact-specific information used by installinator.
///
/// This document contains information used by installinator to learn about
/// which artifacts to fetch. Unlike
/// [`ArtifactsDocument`](crate::ArtifactsDocument):
///
/// * This document is treated as an opaque blob by Wicketd and Nexus, since
///   we'd like previous versions of those services to be able to process newer
///   versions of this document.
/// * There are no backwards compatibility constraints for this document. The
///   version of installinator that processes this document is the same as the
///   version of tufaceous that creates it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InstallinatorDocument {
    pub system_version: Version,
    pub artifacts: Vec<InstallinatorArtifact>,
}

impl InstallinatorDocument {
    /// Creates an installinator document with the provided system version and
    /// an empty list of artifacts.
    pub fn empty(system_version: Version) -> Self {
        Self { system_version, artifacts: Vec::new() }
    }

    pub fn file_name(&self) -> String {
        format!("installinator_document-{}.json", self.system_version)
    }
}

/// Describes an artifact available to installinator.
///
/// The fields here match [`Artifact`](crate::Artifact).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InstallinatorArtifact {
    pub name: String,
    /// The kind of artifact.
    ///
    /// This is an [`InstallinatorArtifactKind`] rather than an
    /// [`ArtifactKind`](crate::ArtifactKind) because there aren't any backwards
    /// compatibility constraints with `InstallinatorArtifact`.
    pub kind: InstallinatorArtifactKind,
    pub hash: ArtifactHash,
}

/// The artifact kind for an installinator artifact.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallinatorArtifactKind {
    /// The host phase 2 artifact.
    ///
    /// This is extracted from the composite host artifact.
    HostPhase2,
    /// The composite control plane artifact.
    ControlPlane,
    /// Measurement Corpus
    MeasurementCorpus,
}
