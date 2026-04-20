// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fmt::Display;
use std::str::FromStr;

use daft::Diffable;
use hex::FromHexError;
use serde::Deserialize;
use serde::Serialize;

use crate::ArtifactVersion;
use crate::DisplayTags;
use crate::KnownArtifactTags;

/// An artifact in a repository.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
pub struct Artifact {
    /// The TUF target name, if this value is associated with a loaded
    /// repository.
    ///
    /// If you are instantiating this struct from other records (such as a
    /// database), you can use `String::new()` here.
    pub target_name: String,

    /// The version of the artifact.
    pub version: ArtifactVersion,

    /// The artifact's tags.
    ///
    /// Tags describe how an artifact is to be used by the control plane.
    /// In this form, they are an arbitrary mapping of string keys to string
    /// values. Using [`Artifact::known_tags`], they can be (fallibly) converted
    /// into a strongly-typed description of the artifact.
    ///
    /// When recording artifacts for later use, the control plane must always
    /// record these tags as-is, even if `Artifact::known_tags` returns `None`.
    pub tags: BTreeMap<String, String>,

    /// The SHA256 checksum of the artifact.
    pub hash: ArtifactHash,

    /// The length of the artifact in bytes.
    pub length: u64,
}

impl Artifact {
    /// Resolves [`Artifact::tags`] into [`KnownArtifactTags`].
    ///
    /// Returns `None` if the tags do not resolve to any known artifact.
    pub fn known_tags(&self) -> Option<KnownArtifactTags> {
        KnownArtifactTags::from_tags(self.tags.clone()).ok()
    }

    /// Returns an adapter for displaying [`Artifact::tags`] as a human-readable
    /// string.
    pub fn display_tags(&self) -> DisplayTags<'_> {
        DisplayTags::from(&self.tags)
    }
}

/// The SHA256 checksum of an artifact.
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

impl Debug for ArtifactHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ArtifactHash").field(&hex::encode(self.0)).finish()
    }
}

impl Display for ArtifactHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&hex::encode(self.0), f)
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

/// Produce an OpenAPI schema describing a hex array of a specific length (e.g.,
/// a hash digest).
#[cfg(feature = "schemars")]
fn hex_schema<const N: usize>(
    generator: &mut schemars::SchemaGenerator,
) -> schemars::schema::Schema {
    use schemars::JsonSchema;

    let mut schema: schemars::schema::SchemaObject =
        <String>::json_schema(generator).into();
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
