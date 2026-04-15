// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;

/// Structured repository-level metadata stored in `artifacts-v2.json`.
//
// NOTE: Similar to KnownArtifactTags, this struct must serialize to
// and deserialize from a mapping of string keys to string values. The
// `metadata_roundtrip` test covers this (crate::map::to_map panics when debug
// assertions are enabled if this does not hold).
//
// Additionally, it is a requirement that all fields are optional; it must
// be possible to deserialize this struct from older metadata, and the oldest
// metadata is no metadata at all.
//
// As such, a couple of recommendations for adding new fields:
// 1. Wrap all fields in [`Option`] and mark with
//    `#[serde(skip_serializing_if = "Option::is_none")]`.
// 2. Mark nested structs with `#[serde(flatten)]`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
pub struct Metadata {
    // We don't actually have any metadata yet, but we wanted to set up the
    // scaffolding to make it possible in the future.
}

impl Metadata {
    /// Deserialize structured metadata from a string mapping.
    pub fn from_map(
        map: BTreeMap<String, String>,
    ) -> Result<Self, serde_json::Error> {
        crate::map::from_map(map)
    }

    /// Serialize structured metadata into a string mapping.
    pub fn to_map(&self) -> BTreeMap<String, String> {
        crate::map::to_map(self)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use test_strategy::proptest;

    use crate::Metadata;

    /// **Do not change this test when adding new metadata.** This structure
    /// must be capable of deserializing older metadata, and the oldest metadata
    /// is no metadata at all.
    #[test]
    fn deserialize_from_empty() {
        Metadata::from_map(BTreeMap::new()).unwrap();
    }

    #[test]
    fn default_is_empty() {
        assert!(Metadata::default().to_map().is_empty());
    }

    #[proptest]
    fn metadata_roundtrip(metadata: Metadata) {
        let map = metadata.to_map();
        assert_eq!(Metadata::from_map(map).unwrap(), metadata);
    }
}
