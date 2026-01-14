// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::fmt::Debug;
use std::fmt::Display;
use std::sync::LazyLock;

use serde::Deserialize;
use serde::Serialize;

const CA_LIST: [(&str, &str); 9] = [
    (
        "f62eb434dd27302521d12958a7c3c18c69f6e0239361654f0a09e5cc554e0fab",
        "production-cosmo-rot",
    ),
    (
        "5796ee3433f840519c3bcde73e19ee82ccb6af3857eddaabb928b8d9726d93c0",
        "production-gimlet-rot",
    ),
    (
        "31942f8d53dc908c5cb338bdcecb204785fa87834e8b18f706fc972a42886c8b",
        "production-psc-rot",
    ),
    (
        "5c69a42ee1f1e6cd5f356d14f81d46f8dbee783bb28777334226c689f169c0eb",
        "production-sidecar-rot",
    ),
    (
        "855a51518d13dd696a8102a5b2436bb2e8c39a6c0102909fce0a32adc6b76fb4",
        "staging-cosmo-rot",
    ),
    (
        "11594bb5548a757e918e6fe056e2ad9e084297c9555417a025d8788eacf55daf",
        "staging-gimlet-rot",
    ),
    (
        "f592d8f109b81881221eed5af6438abad9b5df8c220b9129c03763e7e10b22c7",
        "staging-psc-rot",
    ),
    (
        "1432cc4cfe5688c51b55546fe37837c753cfbc89e8c3c6aabcf977fdf0c41e27",
        "staging-sidecar-rot",
    ),
    (
        "84332ef8279df87fbb759dc3866cbc50cd246fbb5a64705a7e60ba86bf01c27d",
        "test-bart",
    ),
];
static CA_MAP: LazyLock<HashMap<&str, &str>> =
    LazyLock::new(|| HashMap::from(CA_LIST));

#[derive(
    Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
#[serde(transparent)]
pub struct Sign(pub Option<String>);

impl Sign {
    pub const UNSIGNED: Sign = Sign(None);

    pub fn new(sign: Option<String>) -> Self {
        Self(sign)
    }

    pub fn is_signed(&self) -> bool {
        self.0.is_some()
    }

    pub fn is_unsigned(&self) -> bool {
        self.0.is_none()
    }

    pub fn friendly_ca_name(&self) -> Option<&'static str> {
        let inner = self.0.as_deref()?;
        CA_MAP.get(inner).copied()
    }
}

impl Debug for Sign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl Display for Sign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.as_deref() {
            Some(inner) => {
                let s = CA_MAP.get(inner).copied().unwrap_or(inner);
                write!(f, "{s}")
            }
            None => write!(f, "unsigned"),
        }
    }
}

impl<T> From<T> for Sign
where
    Option<String>: From<T>,
{
    fn from(sign: T) -> Self {
        Self(sign.into())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::sign::CA_LIST;
    use crate::sign::CA_MAP;

    #[test]
    fn ensure_consistency() {
        // no duplicate keys
        assert_eq!(CA_MAP.len(), CA_LIST.len());
        // no duplicate values
        let values = CA_MAP.values().collect::<HashSet<_>>();
        assert_eq!(values.len(), CA_LIST.len());
        // CA_LIST is ordered by friendly name
        for window in CA_LIST.windows(2) {
            let [(_, v1), (_, v2)] = window else {
                panic!("slice::windows is broken")
            };
            assert!(v1 < v2, "{v1} incorrectly placed before {v2} in CA_LIST");
        }
    }
}
