// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::btree_map::IntoValues;
use std::collections::btree_map::Values;
use std::fmt::Display;
use std::iter::Flatten;

use serde::Deserialize;
use serde::Serialize;

use crate::ArtifactHash;
use crate::ArtifactVersion;
use crate::KnownArtifactTags;

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize,
)]
pub struct Artifact {
    pub target_name: String,
    pub version: ArtifactVersion,
    pub tags: BTreeMap<String, String>,
    pub hash: ArtifactHash,
    pub length: u64,
}

impl Artifact {
    /// Clones this artifact's `version` and `tags` into an [`ArtifactId`].
    pub fn id(&self) -> ArtifactId {
        ArtifactId { version: self.version.clone(), tags: self.tags.clone() }
    }

    pub fn known_tags(&self) -> Option<KnownArtifactTags> {
        KnownArtifactTags::from_tags(&self.tags).ok()
    }

    pub fn display_tags(&self) -> DisplayTags<'_> {
        DisplayTags(Cow::Borrowed(&self.tags))
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "schemars"), derive(schemars::JsonSchema))]
pub struct ArtifactId {
    pub version: ArtifactVersion,
    pub tags: BTreeMap<String, String>,
}

impl ArtifactId {
    pub fn known_tags(&self) -> Option<KnownArtifactTags> {
        KnownArtifactTags::from_tags(&self.tags).ok()
    }

    pub fn display_tags(&self) -> DisplayTags<'_> {
        DisplayTags(Cow::Borrowed(&self.tags))
    }
}

impl From<Artifact> for ArtifactId {
    fn from(artifact: Artifact) -> Self {
        ArtifactId { version: artifact.version, tags: artifact.tags }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Artifacts {
    inner: BTreeMap<Option<KnownArtifactTags>, BTreeSet<Artifact>>,
}

impl Artifacts {
    pub fn new(iter: impl IntoIterator<Item = Artifact>) -> Self {
        Self::from_iter(iter)
    }

    pub fn len(&self) -> usize {
        self.inner.values().map(BTreeSet::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        debug_assert_eq!(self.len(), 0);
        self.inner.is_empty()
    }

    pub fn insert(&mut self, artifact: Artifact) {
        self.inner.entry(artifact.known_tags()).or_default().insert(artifact);
    }

    pub fn get(&self, tags: KnownArtifactTags) -> Result<&Artifact, GetError> {
        let vec = self.inner.get(&Some(tags)).ok_or(GetError::NotFound)?;
        if vec.len() == 1
            && let Some(artifact) = vec.first()
        {
            Ok(artifact)
        } else {
            Err(GetError::TooMany)
        }
    }

    pub fn get_all(
        &self,
        tags: KnownArtifactTags,
    ) -> impl Iterator<Item = &Artifact> {
        self.inner.get(&Some(tags)).map(BTreeSet::iter).unwrap_or_default()
    }

    pub fn contains(&self, artifact: &Artifact) -> bool {
        self.inner
            .get(&artifact.known_tags())
            .is_some_and(|set| set.contains(artifact))
    }

    pub fn filter_tags(
        &self,
        mut predicate: impl FnMut(&KnownArtifactTags) -> bool,
    ) -> impl Iterator<Item = &Artifact> {
        self.inner
            .iter()
            .filter_map(move |(tags, artifacts)| {
                predicate(tags.as_ref()?).then_some(artifacts)
            })
            .flatten()
    }

    pub fn iter(&self) -> Iter<'_> {
        Iter { inner: self.inner.values().flatten() }
    }
}

impl Extend<Artifact> for Artifacts {
    fn extend<T: IntoIterator<Item = Artifact>>(&mut self, iter: T) {
        for artifact in iter {
            self.insert(artifact);
        }
    }
}

impl FromIterator<Artifact> for Artifacts {
    fn from_iter<T: IntoIterator<Item = Artifact>>(iter: T) -> Self {
        let mut artifacts = Self::default();
        artifacts.extend(iter);
        artifacts
    }
}

impl IntoIterator for Artifacts {
    type Item = Artifact;
    type IntoIter = IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter { inner: self.inner.into_values().flatten() }
    }
}

impl<'a> IntoIterator for &'a Artifacts {
    type Item = &'a Artifact;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'de> Deserialize<'de> for Artifacts {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Artifacts;

            fn expecting(
                &self,
                f: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                write!(f, "a sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Artifacts, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                std::iter::from_fn(|| seq.next_element().transpose()).collect()
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

impl Serialize for Artifacts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.iter())
    }
}

#[derive(Debug)]
pub struct IntoIter {
    inner: Flatten<IntoValues<Option<KnownArtifactTags>, BTreeSet<Artifact>>>,
}

impl Iterator for IntoIter {
    type Item = Artifact;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

#[derive(Debug, Clone)]
pub struct Iter<'a> {
    inner: Flatten<Values<'a, Option<KnownArtifactTags>, BTreeSet<Artifact>>>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Artifact;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GetError {
    #[error("artifact not found")]
    NotFound,
    #[error("more than one artifact found")]
    TooMany,
}
