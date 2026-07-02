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
/// There are (normally) no backwards compatibility constraints for this
/// document, because the version of Tufaceous used to generate it (via the
/// control plane releng tooling) is the same as the version of Tufaceous used
/// to read it (via Installinator), and this is enforced by the use of workspace
/// dependencies in Omicron.
///
/// Both Wicketd and Nexus treat this document as an opaque blob, since we'd
/// like previous versions of those services to be able to start the "sled
/// recovery" workflow in which the recovery phase 1 image is flashed to a
/// sled, which retrieves the recovery phase 2 image via the SP, which starts
/// Installinator and retrieves the artifacts required to boot normally via the
/// bootstrap network.
///
/// # v1 compatibility notes
///
/// In the first release after Tufaceous v2 is integrated in Wicket and
/// Installinator, this will be the situation mupdate is in:
///
/// - Installinator is using Tufaceous v2 to read the Installinator document.
/// - Wicket on the currently-running system is using Tufaceous v1, and does
///   not extract the composite control plane artifact; thus the individual zone
///   artifacts are not available via the bootstrap network.
/// - The Installinator document was written by Tufaceous v1, because Wicket
///   can only understand v1 repos. (Tufaceous v2 will not generate v1 repos, so
///   releng will use both versions until we can stop generating v1 repos.)
///
/// This violates the constraint that the same version of Tufaceous is used to
/// generate and read the Installinator document. So, Installinator needs its
/// own backwards compatibility code, which some temporary code in this module
/// supports:
///
/// - `name` is accepted as an alias for [`InstallinatorArtifact::file_name`].
///   We renamed this field in Tufaceous v2 for clarity.
/// - `ControlPlane` is an accepted variant for [`InstallinatorArtifactKind`].
///   This indicates to Installinator that an older version of Wicket was used
///   to read the repository, and that it will need to fetch the composite
///   artifact and unpack the control plane zones.
///
/// These temporary compatibility shims can be removed (along with
/// Installinator's v1 compatibility code) in the control plane release after
/// Tufaceous v2 was integrated into Wicket and Installinator, assuming that we
/// continue to disallow skipping major versions during upgrades.
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
    // (temporary alias; see "v1 compatibility notes" above)
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
    /// A tarball of control plane zones. See "v1 compatibility notes" on
    /// [`InstallinatorDocument`].
    ControlPlane,
}
