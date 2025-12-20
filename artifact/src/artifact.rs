// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::IntoValues;
use std::collections::hash_map::Values;
use std::iter::Flatten;

use crate::ArtifactHash;
use crate::ArtifactVersion;
use crate::KnownArtifactTags;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Artifact {
    pub target_name: String,
    pub version: ArtifactVersion,
    pub tags: BTreeMap<String, String>,
    pub sha256: ArtifactHash,
    pub length: u64,
}

impl Artifact {
    pub fn known_tags(&self) -> Option<KnownArtifactTags> {
        KnownArtifactTags::from_tags(&self.tags).ok()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Artifacts {
    inner: HashMap<Option<KnownArtifactTags>, HashSet<Artifact>>,
}

impl Artifacts {
    pub fn new(iter: impl IntoIterator<Item = Artifact>) -> Self {
        Self::from_iter(iter)
    }

    pub fn len(&self) -> usize {
        self.inner.values().map(HashSet::len).sum()
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
            && let Some(artifact) = vec.iter().next()
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
        self.inner.get(&Some(tags)).map(HashSet::iter).unwrap_or_default()
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

#[derive(Debug)]
pub struct IntoIter {
    inner: Flatten<IntoValues<Option<KnownArtifactTags>, HashSet<Artifact>>>,
}

impl Iterator for IntoIter {
    type Item = Artifact;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

#[derive(Debug, Clone)]
pub struct Iter<'a> {
    inner: Flatten<Values<'a, Option<KnownArtifactTags>, HashSet<Artifact>>>,
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
