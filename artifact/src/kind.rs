// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{borrow::Cow, convert::Infallible, fmt, str::FromStr};

use daft::Diffable;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, EnumString, IntoEnumIterator};
use thiserror::Error;

/// The kind of artifact we are dealing with.
///
/// To ensure older versions of Nexus can work with update repositories that
/// describe artifact kinds it is not yet aware of, this is a newtype wrapper
/// around a string. The set of known artifact kinds is described in
/// [`KnownArtifactKind`], and this type has conversions to and from it.
#[derive(
    Debug,
    Diffable,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    Deserialize,
    Serialize,
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(transparent)]
pub struct ArtifactKind(Cow<'static, str>);

impl ArtifactKind {
    /// Creates a new `ArtifactKind` from a string.
    pub fn new(kind: String) -> Self {
        Self(kind.into())
    }

    /// Creates a new `ArtifactKind` from a static string.
    pub const fn from_static(kind: &'static str) -> Self {
        Self(Cow::Borrowed(kind))
    }

    /// Creates a new `ArtifactKind` from a known kind.
    pub fn from_known(kind: KnownArtifactKind) -> Self {
        Self::new(kind.to_string())
    }

    /// Returns the kind as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Converts self to a `KnownArtifactKind`, if it is known.
    pub fn to_known(&self) -> Option<KnownArtifactKind> {
        self.0.parse().ok()
    }
}

/// These artifact kinds are not stored anywhere, but are derived from stored
/// kinds and used as internal identifiers.
impl ArtifactKind {
    /// Gimlet root of trust bootloader slot image identifier.
    ///
    /// Derived from [`KnownArtifactKind::GimletRotBootloader`].
    pub const GIMLET_ROT_STAGE0: Self =
        Self::from_static("gimlet_rot_bootloader");

    /// Gimlet root of trust A slot image identifier.
    ///
    /// Derived from [`KnownArtifactKind::GimletRot`].
    pub const GIMLET_ROT_IMAGE_A: Self =
        Self::from_static("gimlet_rot_image_a");

    /// Gimlet root of trust B slot image identifier.
    ///
    /// Derived from [`KnownArtifactKind::GimletRot`].
    pub const GIMLET_ROT_IMAGE_B: Self =
        Self::from_static("gimlet_rot_image_b");

    /// PSC root of trust stage0 image identifier.
    ///
    /// Derived from [`KnownArtifactKind::PscRotBootloader`].
    pub const PSC_ROT_STAGE0: Self = Self::from_static("psc_rot_bootloader");

    /// PSC root of trust A slot image identifier.
    ///
    /// Derived from [`KnownArtifactKind::PscRot`].
    pub const PSC_ROT_IMAGE_A: Self = Self::from_static("psc_rot_image_a");

    /// PSC root of trust B slot image identifier.
    ///
    /// Derived from [`KnownArtifactKind::PscRot`].
    pub const PSC_ROT_IMAGE_B: Self = Self::from_static("psc_rot_image_b");

    /// Switch root of trust A slot image identifier.
    ///
    /// Derived from [`KnownArtifactKind::SwitchRotBootloader`].
    pub const SWITCH_ROT_STAGE0: Self =
        Self::from_static("switch_rot_bootloader");

    /// Switch root of trust A slot image identifier.
    ///
    /// Derived from [`KnownArtifactKind::SwitchRot`].
    pub const SWITCH_ROT_IMAGE_A: Self =
        Self::from_static("switch_rot_image_a");

    /// Switch root of trust B slot image identifier.
    ///
    /// Derived from [`KnownArtifactKind::SwitchRot`].
    pub const SWITCH_ROT_IMAGE_B: Self =
        Self::from_static("switch_rot_image_b");

    /// Host phase 1 identifier.
    ///
    /// Derived from [`KnownArtifactKind::Host`].
    pub const HOST_PHASE_1: Self = Self::from_static("host_phase_1");

    /// Host phase 2 identifier.
    ///
    /// Derived from [`KnownArtifactKind::Host`].
    pub const HOST_PHASE_2: Self = Self::from_static("host_phase_2");

    /// Trampoline phase 1 identifier.
    ///
    /// Derived from [`KnownArtifactKind::Trampoline`].
    pub const TRAMPOLINE_PHASE_1: Self =
        Self::from_static("trampoline_phase_1");

    /// Trampoline phase 2 identifier.
    ///
    /// Derived from [`KnownArtifactKind::Trampoline`].
    pub const TRAMPOLINE_PHASE_2: Self =
        Self::from_static("trampoline_phase_2");
}

impl From<KnownArtifactKind> for ArtifactKind {
    fn from(kind: KnownArtifactKind) -> Self {
        Self::from_known(kind)
    }
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ArtifactKind {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s.to_owned()))
    }
}

/// Kinds of update artifacts, as used by Nexus to determine what updates are available and by
/// sled-agent to determine how to apply an update when asked.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Ord,
    PartialOrd,
    Display,
    EnumString,
    Deserialize,
    Serialize,
    EnumIter,
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum KnownArtifactKind {
    // Sled Artifacts
    GimletSp,
    GimletRot,
    GimletRotBootloader,
    Host,
    Trampoline,
    /// Installinator document identifier.
    ///
    /// While the installinator document is a metadata file similar to
    /// [`ArtifactsDocument`](crate::ArtifactsDocument), Wicketd and Nexus treat
    /// it as an opaque single-unit artifact to avoid backwards compatibility
    /// issues.
    InstallinatorDocument,
    /// Composite artifact of all control plane zones
    ControlPlane,
    /// Individual control plane zone
    Zone,
    /// MeasurementCorpus
    MeasurementCorpus,

    // PSC Artifacts
    PscSp,
    PscRot,
    PscRotBootloader,

    // Switch Artifacts
    SwitchSp,
    SwitchRot,
    SwitchRotBootloader,
}

impl KnownArtifactKind {
    /// For an RoT variant, returns A and B deployment unit kinds.
    pub fn rot_a_and_b_kinds(
        self,
    ) -> Result<(ArtifactKind, ArtifactKind), NotRotVariantError> {
        match self {
            KnownArtifactKind::GimletRot => Ok((
                ArtifactKind::GIMLET_ROT_IMAGE_A,
                ArtifactKind::GIMLET_ROT_IMAGE_B,
            )),
            KnownArtifactKind::PscRot => Ok((
                ArtifactKind::PSC_ROT_IMAGE_A,
                ArtifactKind::PSC_ROT_IMAGE_B,
            )),
            KnownArtifactKind::SwitchRot => Ok((
                ArtifactKind::SWITCH_ROT_IMAGE_A,
                ArtifactKind::SWITCH_ROT_IMAGE_B,
            )),
            KnownArtifactKind::GimletSp
            | KnownArtifactKind::GimletRotBootloader
            | KnownArtifactKind::Host
            | KnownArtifactKind::Trampoline
            | KnownArtifactKind::InstallinatorDocument
            | KnownArtifactKind::MeasurementCorpus
            | KnownArtifactKind::ControlPlane
            | KnownArtifactKind::Zone
            | KnownArtifactKind::PscSp
            | KnownArtifactKind::PscRotBootloader
            | KnownArtifactKind::SwitchSp
            | KnownArtifactKind::SwitchRotBootloader => {
                Err(NotRotVariantError(self))
            }
        }
    }

    /// Returns an iterator over all the variants in this struct.
    ///
    /// This is provided as a helper so dependent packages don't have to pull in
    /// strum explicitly.
    pub fn iter() -> KnownArtifactKindIter {
        <Self as IntoEnumIterator>::iter()
    }
}

#[derive(Debug, Error)]
#[error("expected an RoT variant, found {0:?}")]
pub struct NotRotVariantError(KnownArtifactKind);

#[cfg(test)]
mod tests {
    use super::{ArtifactKind, KnownArtifactKind};

    #[test]
    fn serde_artifact_kind() {
        assert_eq!(
            serde_json::from_str::<ArtifactKind>("\"gimlet_sp\"")
                .unwrap()
                .to_known(),
            Some(KnownArtifactKind::GimletSp)
        );
        assert_eq!(
            serde_json::from_str::<ArtifactKind>("\"fhqwhgads\"")
                .unwrap()
                .to_known(),
            None,
        );
        assert!(serde_json::from_str::<ArtifactKind>("null").is_err());

        assert_eq!(
            serde_json::to_string(&ArtifactKind::from_known(
                KnownArtifactKind::GimletSp
            ))
            .unwrap(),
            "\"gimlet_sp\""
        );
        assert_eq!(
            serde_json::to_string(&ArtifactKind::new("fhqwhgads".to_string()))
                .unwrap(),
            "\"fhqwhgads\""
        );
    }

    #[test]
    fn known_artifact_kind_roundtrip() {
        for kind in KnownArtifactKind::iter() {
            let as_string = kind.to_string();
            let kind2 = as_string.parse::<KnownArtifactKind>().unwrap_or_else(
                |error| panic!("error parsing kind {as_string}: {error}"),
            );
            assert_eq!(kind, kind2);
        }
    }

    #[test]
    fn display_respects_padding() {
        let kind = ArtifactKind::from_static("foo");
        assert_eq!(format!("{kind:x>10}"), "xxxxxxxfoo");

        let kind = KnownArtifactKind::Host;
        assert_eq!(format!("{kind:x>10}"), "xxxxxxhost");
    }
}
