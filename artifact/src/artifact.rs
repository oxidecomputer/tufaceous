// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::{ArtifactKind, ArtifactVersion};

/// Description of the `artifacts.json` target found in rack update
/// repositories.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArtifactsDocument {
    pub system_version: Version,
    pub artifacts: Vec<Artifact>,
}

impl ArtifactsDocument {
    /// Creates an artifacts document with the provided system version and an
    /// empty list of artifacts.
    pub fn empty(system_version: Version) -> Self {
        Self { system_version, artifacts: Vec::new() }
    }
}

/// Describes an artifact available in the repository.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Artifact {
    /// Used to differentiate between different series of artifacts of the same
    /// kind. This is used by the control plane to select the correct artifact.
    ///
    /// For SP and ROT images ([`GimletSp`](crate::KnownArtifactKind::GimletSp),
    /// [`GimletRot`](crate::KnownArtifactKind::GimletRot),
    /// [`PscSp`](crate::KnownArtifactKind::PscSp),
    /// [`PscRot`](crate::KnownArtifactKind::PscRot),
    /// [`SwitchSp`](crate::KnownArtifactKind::SwitchSp),
    /// [`SwitchRot`](crate::KnownArtifactKind::SwitchRot)), `name` is the value
    /// of the board (`BORD`) tag in the image caboose.
    ///
    /// In the future when
    /// [`ControlPlane`](crate::KnownArtifactKind::ControlPlane) is split up
    /// into separate zones, `name` will be the zone name.
    pub name: String,
    pub version: ArtifactVersion,
    pub kind: ArtifactKind,
    pub target: String,
}
