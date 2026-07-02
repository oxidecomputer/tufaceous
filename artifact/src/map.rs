// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Utilities for mappings of string keys to string values
//! (`BTreeMap<String, String>`).
//!
//! Tufaceous uses these string mappings for future-proofing artifact-level
//! metadata ("tags") and repository-level metadata, so that all of the
//! repository information can be losslessly entered into a database even if an
//! older version of Tufaceous is used to read a repository.

// TODO: This (as of writing) is the only use of serde_json in the entire
// tufaceous-artifact crate, and it's not even for writing/parsing JSON.
// This is "unfortunate but reasonable": anything we expect to be using
// tufaceous-artifact is highly likely to use serde_json anyway.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Creates a struct `D` from a string mapping, round-tripping via
/// `serde_json::Value`.
///
/// This could someday be implemented without round-tripping through
/// `serde_json::Value` but implementing a proper deserializer is a lot of
/// effort that, as of writing this comment, is out of scope.
pub(crate) fn from_map<D: DeserializeOwned>(
    map: BTreeMap<String, String>,
) -> Result<D, serde_json::Error> {
    D::deserialize(map.into_iter().collect::<serde_json::Value>())
}

/// Creates a string mapping from a struct `S`, round-tripping via
/// `serde_json::Value`.
///
/// This could someday be implemented without round-tripping through
/// `serde_json::Value` but implementing a proper serializer is a lot of effort
/// that, as of writing this comment, is out of scope.
pub(crate) fn to_map<S: Serialize>(
    s: &S,
) -> Result<BTreeMap<String, String>, serde_json::Error> {
    BTreeMap::deserialize(serde_json::to_value(s)?)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    #[test]
    fn from_optional_string() {
        #[derive(Debug, PartialEq, Deserialize)]
        struct Map {
            optional: Option<String>,
        }

        let mut tags = BTreeMap::new();
        assert_eq!(
            super::from_map::<Map>(tags.clone()).unwrap(),
            Map { optional: None }
        );
        tags.insert("optional".to_owned(), "value".to_owned());
        assert_eq!(
            super::from_map::<Map>(tags).unwrap(),
            Map { optional: Some("value".to_owned()) }
        );
    }
}
