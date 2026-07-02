// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;

use semver::Version;
use serde::Deserialize;
use serde::Serialize;
use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::KnownArtifactTags;

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ArtifactSetSchema {
    pub(crate) system_version: Version,
    #[serde(default)]
    pub(crate) artifacts: Vec<ArtifactSchema>,
    #[serde(default)]
    pub(crate) metadata: BTreeMap<String, String>,
}

impl ArtifactSetSchema {
    pub(crate) const TARGET_NAME: &str = "artifacts-v2.json";
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub(crate) struct ArtifactSchema {
    pub(crate) target_name: String,
    pub(crate) version: ArtifactVersion,
    pub(crate) tags: BTreeMap<String, String>,
}

impl ArtifactSchema {
    pub(crate) fn known_tags(&self) -> Option<KnownArtifactTags> {
        KnownArtifactTags::from_tags(self.tags.clone()).ok()
    }
}

impl AsRef<ArtifactSchema> for ArtifactSchema {
    fn as_ref(&self) -> &ArtifactSchema {
        self
    }
}
