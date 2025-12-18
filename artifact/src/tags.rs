// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;
use serde::de::value::MapDeserializer;

use crate::InstallinatorArtifactKind;

/// Sets of artifact tags known to the control plane.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum KnownArtifactTags {
    /// JSON document describing the artifacts installinator is responsible for
    /// writing during mupdate and sled recovery.
    InstallinatorDocument {},

    /// CORIM manifest for remote attestation.
    MeasurementCorpus {},

    /// Phase 1 OS image, written to flash. Differs based on the target board.
    OsPhase1 { variant: OsVariant, board: OsBoard },

    /// Phase 2 OS image, a ZFS pool with an Oxide-specific header written to
    /// M.2 storage. Common across all target boards.
    OsPhase2 { variant: OsVariant },

    /// Hubris archive for a Root of Trust image.
    Rot {
        /// The `BORD` field in the caboose (such as `oxide-rot-1`).
        board: String,
        /// The `SIGN` field in the caboose. This is the Root Key Table Hash
        /// (RKTH).
        ///
        /// For unsigned images this will not be present; this will generally
        /// never occur in release repos but can be useful on hardware that has
        /// not fully made it through manufacturing yet.
        #[serde(skip_serializing_if = "Option::is_none")]
        sign: Option<String>,
        /// ROT images are compiled for two different locations in flash; this
        /// identifies which slot this image belongs to.
        slot: RotSlot,
    },

    /// Hubris archive for a Root of Trust bootloader.
    RotBootloader {
        /// The `BORD` field in the caboose (such as `oxide-rot-1`).
        board: String,
        /// The `SIGN` field in the caboose. This is the Root Key Table Hash
        /// (RKTH).
        ///
        /// For unsigned images this will not be present; this will generally
        /// never occur in release repos but can be useful on hardware that has
        /// not fully made it through manufacturing yet.
        #[serde(skip_serializing_if = "Option::is_none")]
        sign: Option<String>,
    },

    /// Hubris archive for a Service Processor image.
    Sp {
        /// The `BORD` field in the caboose (such as `gimlet-d` or `cosmo-b`).
        board: String,
    },

    /// Tarball of a Helios zone image.
    Zone {
        /// The zone name, as self-identified in the tarball's `oxide.json`
        /// file. This may differ from the filename on disk.
        name: String,
    },
}

impl KnownArtifactTags {
    pub fn from_tags(
        tags: &BTreeMap<String, String>,
    ) -> Result<Self, serde::de::value::Error> {
        Self::deserialize(MapDeserializer::new(
            tags.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        ))
    }

    pub fn to_tags(&self) -> BTreeMap<String, String> {
        self.to_tags_impl().unwrap_or_default()
    }

    fn to_tags_impl(&self) -> Option<BTreeMap<String, String>> {
        let value = serde_json::to_value(self).ok()?;
        let serde_json::Value::Object(map) = value else { return None };
        map.into_iter()
            .map(|(k, v)| match v {
                serde_json::Value::String(v) => Some((k, v)),
                _ => None,
            })
            .collect()
    }

    pub fn to_installinator(&self) -> Option<InstallinatorArtifactKind> {
        match self {
            KnownArtifactTags::MeasurementCorpus {} => {
                Some(InstallinatorArtifactKind::MeasurementCorpus)
            }
            KnownArtifactTags::OsPhase2 { variant: OsVariant::Host } => {
                Some(InstallinatorArtifactKind::HostPhase2)
            }
            KnownArtifactTags::Zone { name } => {
                Some(InstallinatorArtifactKind::Zone { name: name.clone() })
            }
            _ => None,
        }
    }
}

macro_rules! display_serialize {
    ($ty:ty) => {
        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.serialize(f)
            }
        }
    };
}

/// OS variant artifact tag (host or recovery).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
#[serde(rename_all = "kebab-case")]
pub enum OsVariant {
    Host,
    Recovery,
}
display_serialize!(OsVariant);

/// OS board artifact tag (gimlet or cosmo).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
#[serde(rename_all = "kebab-case")]
pub enum OsBoard {
    Gimlet,
    Cosmo,
}
display_serialize!(OsBoard);

/// ROT slot artifact tag (A or B).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
pub enum RotSlot {
    A,
    B,
}
display_serialize!(RotSlot);

#[cfg(test)]
mod tests {
    use test_strategy::proptest;

    use crate::KnownArtifactTags;

    #[proptest]
    fn tags_roundtrip(tags: KnownArtifactTags) {
        let tag_map = tags
            .to_tags_impl()
            .expect("serialized value trivially converts to tag map");
        assert_eq!(KnownArtifactTags::from_tags(&tag_map).unwrap(), tags);
    }
}
