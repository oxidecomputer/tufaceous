// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::borrow::Cow;
use std::collections::BTreeSet;

use serde::Deserialize;
use serde::Serialize;

use crate::ArtifactHash;

/// Artifact-specific information used by Installinator.
///
/// This document is treated as an opaque blob by Wicketd and Nexus, since
/// we'd like previous versions of those services to be able to process newer
/// versions of this document.
///
/// There are no backwards compatibility constraints for this document. The
/// version of Installinator that processes this document is the same as the
/// version of tufaceous that creates it.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct InstallinatorDocument {
    pub artifacts: BTreeSet<InstallinatorArtifact>,
}

/// Describes an artifact available to Installinator.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize,
)]
pub struct InstallinatorArtifact {
    #[serde(flatten)]
    pub kind: InstallinatorArtifactKind,
    pub sha256: ArtifactHash,
    /// A file name without directory separators; not necessarily the target
    /// name.
    pub file_name: String,
}

impl InstallinatorArtifact {
    pub fn downgrade(&self) -> InstallinatorArtifactId {
        InstallinatorArtifactId {
            kind: self.kind.downgrade(),
            hash: self.sha256,
        }
    }
}

/// The artifact kind for an Installinator artifact.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize,
)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InstallinatorArtifactKind {
    /// The host phase 2 artifact.
    HostPhase2,
    /// A measurement corpus.
    MeasurementCorpus,
    /// A control plane zone artifact.
    Zone { zone_name: String },
}

impl InstallinatorArtifactKind {
    pub fn downgrade(&self) -> InstallinatorArtifactKindId {
        InstallinatorArtifactKindId(match self {
            InstallinatorArtifactKind::MeasurementCorpus => {
                Cow::Borrowed("measurement_corpus")
            }
            InstallinatorArtifactKind::HostPhase2 => {
                Cow::Borrowed("host_phase2")
            }
            InstallinatorArtifactKind::Zone { zone_name } => {
                Cow::Owned(format!("zone-{zone_name}"))
            }
        })
    }
}

/// Identifies an artifact that Installinator wants or has used.
///
/// Historically this was called `ArtifactHashId` and consists of two
/// strings: `kind` and `hash`. It was developed before the present system
/// of tags representing an artifact kind but remains in use for any
/// Installinator-related interfaces (namely Wicket and MUPdate overrides).
///
/// This schema is stored to disk and should not change.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize,
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct InstallinatorArtifactId {
    pub kind: InstallinatorArtifactKindId,
    pub hash: ArtifactHash,
}

/// Encodes [`InstallinatorArtifactKind`] as a string.
///
/// Used only in [`InstallinatorArtifactId`].
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize,
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(transparent)]
pub struct InstallinatorArtifactKindId(Cow<'static, str>);

impl InstallinatorArtifactKindId {
    pub const INSTALLINATOR_DOCUMENT: Self =
        Self(Cow::Borrowed("installinator_document"));

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
