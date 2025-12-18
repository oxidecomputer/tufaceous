// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::array::TryFromSliceError;
use std::fmt;
use std::str::FromStr;

use daft::Diffable;
use hex::FromHexError;
use serde::Deserialize;
use serde::Serialize;

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

impl TryFrom<&[u8]> for ArtifactHash {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value.try_into().map(Self)
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
