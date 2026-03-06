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

pub(crate) fn to_map<S: Serialize>(s: &S) -> BTreeMap<String, String> {
    // Call `to_map_impl`. On error, panic if debug assertions are enabled,
    // otherwise return `BTreeMap::default()`.
    match to_map_impl(s) {
        Ok(map) => map,
        Err(err) => {
            if cfg!(debug_assertions) {
                panic!(
                    "serializing {} to map should always succeed: {err:?}",
                    std::any::type_name::<S>()
                );
            } else {
                BTreeMap::default()
            }
        }
    }
}

fn to_map_impl<S: Serialize>(
    s: &S,
) -> Result<BTreeMap<String, String>, ToMapError> {
    let value = serde_json::to_value(s)?;
    let serde_json::Value::Object(map) = value else {
        return Err(ToMapError::StructNotObject(Box::new(value)));
    };
    map.into_iter()
        .map(|(key, value)| match value {
            serde_json::Value::String(value) => Ok((key, value)),
            _ => {
                Err(ToMapError::ValueNotString { key, value: Box::new(value) })
            }
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
enum ToMapError {
    #[error("failed to serialize struct")]
    Serialize(#[from] serde_json::Error),
    #[error("struct serialized to {0:?}, not an object")]
    StructNotObject(Box<serde_json::Value>),
    #[error("value for {key:?} serialized to {value:?}, not a string")]
    ValueNotString { key: String, value: Box<serde_json::Value> },
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
