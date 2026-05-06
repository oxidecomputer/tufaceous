// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Display;

use serde::Deserialize;
use serde::Serialize;

use crate::RotKeyTableHash;
use crate::installinator::InstallinatorArtifactKind;

/// Sets of artifact tags known to the control plane.
//
// NOTE: This struct must serialize and deserialize from a mapping of
// string keys to string values. The `tags_roundtrip` test covers this
// (crate::map::to_map returns an error if this does not hold).
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnownArtifactTags {
    /// JSON document describing the artifacts Installinator is responsible for
    /// writing during mupdate and sled recovery.
    InstallinatorDocument,

    /// CoRIM manifest for remote attestation.
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
    /// Resolves known tags from a tag mapping.
    ///
    /// # Errors
    ///
    /// Returns an error if the `kind` tag is missing, not a known kind, or
    /// required tags for that kind are not present.
    pub fn from_tags(
        tags: BTreeMap<String, String>,
    ) -> Result<Self, serde_json::Error> {
        crate::map::from_map(tags)
    }

    /// Converts these known tags to a tag mapping.
    pub fn to_tags(
        &self,
    ) -> Result<BTreeMap<String, String>, serde_json::Error> {
        crate::map::to_map(self)
    }

    /// Converts these tags into an [`InstallinatorArtifactKind`] if this
    /// artifact kind should be included in the Installinator document.
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

impl Display for KnownArtifactTags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tags = self.to_tags().map_err(|_| std::fmt::Error)?;
        DisplayTags::from(tags).fmt(f)
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

/// The inner value of [`KnownArtifactTags::OsPhase1`].
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
pub struct OsPhase1Tags {
    /// OS board artifact tag (gimlet or cosmo).
    pub os_board: OsBoard,
    /// OS variant artifact tag (host or recovery).
    pub os_variant: OsVariant,
}

impl From<OsPhase1Tags> for KnownArtifactTags {
    fn from(tags: OsPhase1Tags) -> Self {
        KnownArtifactTags::OsPhase1(tags)
    }
}

/// The inner value of [`KnownArtifactTags::OsPhase2`].
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
pub struct OsPhase2Tags {
    /// OS variant artifact tag (host or recovery).
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
    /// The host OS.
    Host,
    /// The recovery OS (sometimes called the trampoline OS), which contains
    /// Installinator and is used to install the host OS.
    Recovery,
}
display_serialize!(OsVariant);

/// OS board artifact tag (gimlet, cosmo, etc).
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
#[serde(transparent)]
pub struct OsBoard(pub Cow<'static, str>);

impl OsBoard {
    /// First-generation SP3 compute sled.
    pub const GIMLET: Self = Self(Cow::Borrowed("gimlet"));
    /// Second-generation SP5 compute sled.
    pub const COSMO: Self = Self(Cow::Borrowed("cosmo"));
}

impl Display for OsBoard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

/// The inner value of [`KnownArtifactTags::Rot`].
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
pub struct RotTags {
    /// The `BORD` field in the caboose (such as `oxide-rot-1`).
    pub rot_board: String,
    /// The RoT Key Table Hash (RKTH). This is the `SIGN` field in the caboose.
    ///
    /// For unsigned images this will not be present; this will generally
    /// never occur in release repos but can be useful on hardware that has
    /// not fully made it through manufacturing yet.
    #[serde(skip_serializing_if = "RotKeyTableHash::is_none")]
    pub rot_rkth: RotKeyTableHash,
    /// RoT images are compiled for two different locations in flash; this
    /// identifies which slot this image belongs to.
    pub rot_slot: RotSlot,
}

impl From<RotTags> for KnownArtifactTags {
    fn from(tags: RotTags) -> Self {
        KnownArtifactTags::Rot(tags)
    }
}

/// RoT slot artifact tag (A or B).
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
    /// Slot A.
    A,
    /// Slot B.
    B,
}
display_serialize!(RotSlot);

/// The inner value of [`KnownArtifactTags::RotBootloader`].
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
    #[serde(skip_serializing_if = "RotKeyTableHash::is_none")]
    pub rot_rkth: RotKeyTableHash,
}

impl From<RotBootloaderTags> for KnownArtifactTags {
    fn from(tags: RotBootloaderTags) -> Self {
        KnownArtifactTags::RotBootloader(tags)
    }
}

/// The inner value of [`KnownArtifactTags::Sp`].
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
pub struct SpTags {
    /// The `BORD` field in the caboose (such as `cosmo-b`).
    pub sp_board: String,
}

impl From<SpTags> for KnownArtifactTags {
    fn from(tags: SpTags) -> Self {
        KnownArtifactTags::Sp(tags)
    }
}

/// The inner value of [`KnownArtifactTags::Zone`].
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

/// An adapter that implements [`Display`] for a set of tags.
///
/// This is intended for error and log messages and is not a portable format.
///
/// # Example
///
/// ```
/// # use std::collections::BTreeMap;
/// # use tufaceous_artifact::DisplayTags;
/// let tags = BTreeMap::from([
///     ("foo".to_string(), "yes".to_string()),
///     ("bar".to_string(), "definitely".to_string()),
///     ("kind".to_string(), "thing".to_string()),
/// ]);
/// assert_eq!(
///     DisplayTags::from(&tags).to_string(),
///     "kind=thing,bar=definitely,foo=yes"
/// );
/// ```
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
    use crate::RotKeyTableHash;
    use crate::RotSlot;
    use crate::RotTags;

    /// [`KnownArtifactTags::to_tags`] is not allowed to fail (but is marked
    /// fallible because it's Serde under the hood); its result must round trip
    /// back to the same value when deserialized.
    #[proptest]
    fn tags_roundtrip(tags: KnownArtifactTags) {
        let map = tags.to_tags().unwrap();
        assert_eq!(KnownArtifactTags::from_tags(map).unwrap(), tags);
    }

    #[test]
    fn rot_rkth() {
        let mut tags = BTreeMap::from([
            ("kind".to_owned(), "rot".to_owned()),
            ("rot_board".to_owned(), "oxide-rot-1".to_owned()),
            // rot_rkth not included
            ("rot_slot".to_owned(), "a".to_owned()),
        ]);
        assert_eq!(
            KnownArtifactTags::from_tags(tags.clone()).unwrap(),
            KnownArtifactTags::Rot(RotTags {
                rot_board: "oxide-rot-1".to_owned(),
                rot_rkth: RotKeyTableHash(None),
                rot_slot: RotSlot::A
            })
        );
        tags.insert("rot_rkth".to_owned(), "meow".to_owned());
        assert_eq!(
            KnownArtifactTags::from_tags(tags).unwrap(),
            KnownArtifactTags::Rot(RotTags {
                rot_board: "oxide-rot-1".to_owned(),
                rot_rkth: RotKeyTableHash(Some("meow".to_owned())),
                rot_slot: RotSlot::A
            })
        );
    }
}
