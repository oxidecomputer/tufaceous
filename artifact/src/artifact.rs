// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{fmt, str::FromStr};

use daft::Diffable;
use hex::FromHexError;
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
    /// The name of the artifacts document: `artifacts.json`.
    pub const FILE_NAME: &'static str = "artifacts.json";

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

/// The hash of an artifact.
#[derive(
    Copy,
    Clone,
    Diffable,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
)]
#[daft(leaf)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[serde(transparent)]
pub struct ArtifactHash(
    #[serde(with = "serde_human_bytes::hex_array")]
    #[cfg_attr(
        feature = "schemars",
        schemars(schema_with = "hex_schema::<32>")
    )]
    pub [u8; 32],
);

impl AsRef<[u8]> for ArtifactHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ArtifactHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ArtifactHash").field(&hex::encode(self.0)).finish()
    }
}

impl fmt::Display for ArtifactHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::encode(self.0).fmt(f)
    }
}

impl FromStr for ArtifactHash {
    type Err = FromHexError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out)?;
        Ok(Self(out))
    }
}

/// A hash-based identifier for an artifact or deployment unit: the kind and
/// hash.
#[derive(
    Debug,
    Diffable,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    Deserialize,
    Serialize,
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct ArtifactHashId {
    /// The kind of artifact this is.
    pub kind: ArtifactKind,

    /// The hash of the artifact.
    pub hash: ArtifactHash,
}

impl fmt::Display for ArtifactHashId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.kind, self.hash)
    }
}

/// Produce an OpenAPI schema describing a hex array of a specific length (e.g.,
/// a hash digest).
#[cfg(feature = "schemars")]
fn hex_schema<const N: usize>(
    gen: &mut schemars::SchemaGenerator,
) -> schemars::schema::Schema {
    use schemars::JsonSchema;

    let mut schema: schemars::schema::SchemaObject =
        <String>::json_schema(gen).into();
    schema.format = Some(format!("hex string ({N} bytes)"));
    schema.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_respects_padding() {
        let h = ArtifactHash([0; 32]);
        assert_eq!(
            format!("{h:x>100}"),
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0000000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
