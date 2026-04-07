// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Display;

use serde::Deserialize;
use serde::Serialize;

use crate::InstallinatorArtifactKind;
use crate::Sign;

/// Sets of artifact tags known to the control plane.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnownArtifactTags {
    /// JSON document describing the artifacts Installinator is responsible for
    /// writing during mupdate and sled recovery.
    InstallinatorDocument,

    /// CORIM manifest for remote attestation.
    MeasurementCorpus,

    /// Phase 1 OS image, written to flash. Differs based on the target board.
    OsPhase1(OsPhase1Tags),

    /// Phase 2 OS image, a ZFS pool with an Oxide-specific header written to
    /// M.2 storage. Common across all target boards.
    OsPhase2(OsPhase2Tags),

    /// Hubris archive for a Root of Trust image.
    Rot(RotTags),

    /// Hubris archive for a Root of Trust bootloader.
    RotBootloader(RotBootloaderTags),

    /// Hubris archive for a Service Processor image.
    Sp(SpTags),

    /// Tarball of a Helios zone image.
    Zone(ZoneTags),
}

impl KnownArtifactTags {
    pub fn display(&self) -> DisplayTags<'static> {
        self.to_tags().into()
    }

    pub fn from_tags(
        tags: BTreeMap<String, String>,
    ) -> Result<Self, serde_json::Error> {
        crate::map::from_map(tags)
    }

    pub fn to_tags(&self) -> BTreeMap<String, String> {
        crate::map::to_map(self)
    }

    pub fn to_installinator(&self) -> Option<InstallinatorArtifactKind> {
        match self {
            KnownArtifactTags::MeasurementCorpus => {
                Some(InstallinatorArtifactKind::MeasurementCorpus)
            }
            KnownArtifactTags::OsPhase2(OsPhase2Tags {
                os_variant: OsVariant::Host,
            }) => Some(InstallinatorArtifactKind::HostPhase2),
            KnownArtifactTags::Zone(ZoneTags { zone_name }) => {
                Some(InstallinatorArtifactKind::Zone {
                    zone_name: zone_name.clone(),
                })
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

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
pub struct OsPhase1Tags {
    pub os_board: OsBoard,
    pub os_variant: OsVariant,
}

impl From<OsPhase1Tags> for KnownArtifactTags {
    fn from(tags: OsPhase1Tags) -> Self {
        KnownArtifactTags::OsPhase1(tags)
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
pub struct OsPhase2Tags {
    pub os_variant: OsVariant,
}

impl From<OsPhase2Tags> for KnownArtifactTags {
    fn from(tags: OsPhase2Tags) -> Self {
        KnownArtifactTags::OsPhase2(tags)
    }
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
#[serde(rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
pub enum OsBoard {
    Gimlet,
    Cosmo,
}
display_serialize!(OsBoard);

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
pub struct RotTags {
    /// The `BORD` field in the caboose (such as `oxide-rot-1`).
    pub rot_board: String,
    /// The `SIGN` field in the caboose. This is the Root Key Table Hash
    /// (RKTH).
    ///
    /// For unsigned images this will not be present; this will generally
    /// never occur in release repos but can be useful on hardware that has
    /// not fully made it through manufacturing yet.
    #[serde(skip_serializing_if = "Sign::is_unsigned")]
    pub rot_sign: Sign,
    /// ROT images are compiled for two different locations in flash; this
    /// identifies which slot this image belongs to.
    pub rot_slot: RotSlot,
}

impl From<RotTags> for KnownArtifactTags {
    fn from(tags: RotTags) -> Self {
        KnownArtifactTags::Rot(tags)
    }
}

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
#[serde(rename_all = "snake_case")]
pub enum RotSlot {
    A,
    B,
}
display_serialize!(RotSlot);

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
pub struct RotBootloaderTags {
    /// The `BORD` field in the caboose (such as `oxide-rot-1`).
    pub rot_board: String,
    /// The `SIGN` field in the caboose. This is the Root Key Table Hash
    /// (RKTH).
    ///
    /// For unsigned images this will not be present; this will generally
    /// never occur in release repos but can be useful on hardware that has
    /// not fully made it through manufacturing yet.
    #[serde(skip_serializing_if = "Sign::is_unsigned")]
    pub rot_sign: Sign,
}

impl From<RotBootloaderTags> for KnownArtifactTags {
    fn from(tags: RotBootloaderTags) -> Self {
        KnownArtifactTags::RotBootloader(tags)
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
pub struct SpTags {
    /// The `BORD` field in the caboose (such as `oxide-rot-1`).
    pub sp_board: String,
}

impl From<SpTags> for KnownArtifactTags {
    fn from(tags: SpTags) -> Self {
        KnownArtifactTags::Sp(tags)
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
pub struct ZoneTags {
    /// The zone name, as self-identified in the tarball's `oxide.json`
    /// file. This may differ from the filename on disk.
    pub zone_name: String,
}

impl From<ZoneTags> for KnownArtifactTags {
    fn from(tags: ZoneTags) -> Self {
        KnownArtifactTags::Zone(tags)
    }
}

#[derive(Debug, Clone)]
pub struct DisplayTags<'a>(pub(crate) Cow<'a, BTreeMap<String, String>>);

impl Display for DisplayTags<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut comma = "";
        let kind = self.0.get_key_value("kind").into_iter();
        let remainder = self.0.iter().filter(|(k, _)| *k != "kind");
        for (key, value) in kind.chain(remainder) {
            write!(f, "{comma}{key}={value}")?;
            comma = ",";
        }
        Ok(())
    }
}

impl From<BTreeMap<String, String>> for DisplayTags<'static> {
    fn from(tags: BTreeMap<String, String>) -> Self {
        Self(Cow::Owned(tags))
    }
}

impl<'a> From<&'a BTreeMap<String, String>> for DisplayTags<'a> {
    fn from(tags: &'a BTreeMap<String, String>) -> Self {
        Self(Cow::Borrowed(tags))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use test_strategy::proptest;

    use crate::KnownArtifactTags;
    use crate::RotSlot;
    use crate::RotTags;
    use crate::Sign;

    #[proptest]
    fn tags_roundtrip(tags: KnownArtifactTags) {
        let map = tags.to_tags();
        assert_eq!(KnownArtifactTags::from_tags(map).unwrap(), tags);
    }

    #[test]
    fn rot_sign() {
        let mut tags = BTreeMap::from([
            ("kind".to_owned(), "rot".to_owned()),
            ("rot_board".to_owned(), "oxide-rot-1".to_owned()),
            // rot_sign not included
            ("rot_slot".to_owned(), "a".to_owned()),
        ]);
        assert_eq!(
            KnownArtifactTags::from_tags(tags.clone()).unwrap(),
            KnownArtifactTags::Rot(RotTags {
                rot_board: "oxide-rot-1".to_owned(),
                rot_sign: Sign::UNSIGNED,
                rot_slot: RotSlot::A
            })
        );
        tags.insert("rot_sign".to_owned(), "meow".to_owned());
        assert_eq!(
            KnownArtifactTags::from_tags(tags).unwrap(),
            KnownArtifactTags::Rot(RotTags {
                rot_board: "oxide-rot-1".to_owned(),
                rot_sign: Sign(Some("meow".to_owned())),
                rot_slot: RotSlot::A
            })
        );
    }
}
