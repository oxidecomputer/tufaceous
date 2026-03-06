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

/// This should always succeed, and callers must use proptests to ensure that
/// it does.
///
/// # Panics
///
/// When debug assertions are enabled, this function panics if
/// `serde_json::to_value` returns a type other than `Value::Object` or an
/// error, or if any of the values in the object are not `Value::String`.
///
/// When debug assertions are disabled, this function returns an empty map
/// if any of these conditions are hit.
pub(crate) fn to_map<S: Serialize>(s: &S) -> BTreeMap<String, String> {
    macro_rules! debug_panic {
        ($($tt:tt)*) => {
            if cfg!(debug_assertions) {
                panic!($($tt)*);
            } else {
                return BTreeMap::default()
            }
        }
    }

    let value_map = match serde_json::to_value(s) {
        Ok(serde_json::Value::Object(map)) => map,
        Ok(not_string) => debug_panic!(
            "{} serialized to {not_string:?}, not an object",
            std::any::type_name::<S>()
        ),
        Err(err) => debug_panic!(
            "failed to serialize {}: {err:?}",
            std::any::type_name::<S>()
        ),
    };
    let mut map = BTreeMap::new();
    for (key, value) in value_map {
        if let serde_json::Value::String(value) = value {
            map.insert(key, value);
        } else {
            debug_panic!(
                "{key:?} in {} serialized to {value:?}, not a string",
                std::any::type_name::<S>()
            );
        }
    }
    map
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
