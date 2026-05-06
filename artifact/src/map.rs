// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;

use serde::Serialize;
use serde::de::DeserializeOwned;

pub(crate) fn from_map<D: DeserializeOwned>(
    map: BTreeMap<String, String>,
) -> Result<D, serde_json::Error> {
    serde_json::from_value(map.into_iter().collect())
}

pub(crate) fn to_map<S: Serialize>(
    s: &S,
) -> Result<BTreeMap<String, String>, serde_json::Error> {
    serde_json::from_value(serde_json::to_value(s)?)
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
