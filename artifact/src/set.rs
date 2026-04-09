// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::btree_map::IntoValues;
use std::collections::btree_map::Values;
use std::collections::btree_set;
use std::iter::Chain;
use std::iter::Flatten;

use serde::Deserialize;
use serde::Serialize;

use crate::Artifact;
use crate::KnownArtifactTags;

/// A set of [`Artifact`]s.
///
/// This type is logically equivalent to `BTreeSet<Artifact>`, but has
/// the additional ability to look up specific artifacts based on their
/// [`KnownArtifactTags`]. (Because of this, artifacts are first sorted by the
/// `Ord` implementation of `KnownArtifactTags`.)
///
/// Artifacts are consistently ordered within this struct, so two sets
/// containing the same artifacts are equal to each other.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArtifactSet {
    known: BTreeMap<KnownArtifactTags, BTreeSet<Artifact>>,
    unknown: BTreeSet<Artifact>,
}

impl ArtifactSet {
    /// Makes a new, empty `ArtifactSet`.
    ///
    /// Does not allocate anything on its own.
    pub const fn new() -> Self {
        Self { known: BTreeMap::new(), unknown: BTreeSet::new() }
    }

    /// Adds an artifact to the set.
    ///
    /// Returns whether the artifact was newly inserted. That is:
    ///
    /// * If the set did not previously contain an equal artifact, `true` is
    ///   returned.
    /// * If the set already contained an equal value, `false` is returned, and
    ///   the entry is not updated.
    pub fn insert(&mut self, artifact: Artifact) -> bool {
        match artifact.known_tags() {
            Some(tags) => self.known.entry(tags).or_default().insert(artifact),
            None => self.unknown.insert(artifact),
        }
    }

    /// Returns the number of artifacts in the set.
    pub fn len(&self) -> usize {
        self.known.values().map(BTreeSet::len).sum::<usize>()
            + self.unknown.len()
    }

    /// Returns `true` if the set contains no artifacts.
    pub fn is_empty(&self) -> bool {
        self.known.is_empty() && self.unknown.is_empty()
    }

    /// Returns `true` if the set contains an artifact equal to `artifact`.
    pub fn contains(&self, artifact: &Artifact) -> bool {
        if let Some(tags) = artifact.known_tags() {
            self.known.get(&tags).is_some_and(|set| set.contains(artifact))
        } else {
            self.unknown.contains(artifact)
        }
    }

    /// Returns the single artifact matching `tags`.
    ///
    /// # Errors
    ///
    /// Returns an error if there is not exactly one artifact matching `tags`.
    pub fn get(&self, tags: &KnownArtifactTags) -> Result<&Artifact, GetError> {
        let set = self.known.get(tags).ok_or(GetError::NotFound)?;
        if set.len() == 1
            && let Some(artifact) = set.first()
        {
            Ok(artifact)
        } else {
            Err(GetError::TooMany)
        }
    }

    /// Returns the set of all artifacts matching `tags`.
    ///
    /// If you are not certain that you want all matching artifacts, prefer
    /// [`ArtifactSet::get`] instead. The control plane must not randomly choose
    /// from matching artifacts when it expects only one.
    pub fn get_all(&self, tags: &KnownArtifactTags) -> &BTreeSet<Artifact> {
        static EMPTY: BTreeSet<Artifact> = BTreeSet::new();
        self.known.get(tags).unwrap_or(&EMPTY)
    }

    /// Returns an iterator of artifacts where the tags match `predicate`.
    ///
    /// # Example
    ///
    /// ```
    /// # use tufaceous_artifact::ArtifactSet;
    /// # use tufaceous_artifact::KnownArtifactTags;
    /// # let set = ArtifactSet::new();
    /// for zone in set
    ///     .filter_tags(|tags| matches!(tags, KnownArtifactTags::Zone { .. }))
    /// {
    ///     // ...
    /// }
    /// ```
    pub fn filter_tags(
        &self,
        mut predicate: impl FnMut(&KnownArtifactTags) -> bool,
    ) -> impl Iterator<Item = &Artifact> {
        self.known
            .iter()
            .filter_map(move |(tags, artifacts)| {
                predicate(tags).then_some(artifacts)
            })
            .flatten()
    }

    /// Returns an iterator over the artifacts in the set.
    pub fn iter(&self) -> Iter<'_> {
        Iter { inner: self.known.values().flatten().chain(&self.unknown) }
    }
}

impl Extend<Artifact> for ArtifactSet {
    fn extend<T: IntoIterator<Item = Artifact>>(&mut self, iter: T) {
        for artifact in iter {
            self.insert(artifact);
        }
    }
}

impl<const N: usize> From<[Artifact; N]> for ArtifactSet {
    fn from(arr: [Artifact; N]) -> Self {
        if N == 0 { ArtifactSet::new() } else { arr.into_iter().collect() }
    }
}

impl FromIterator<Artifact> for ArtifactSet {
    fn from_iter<T: IntoIterator<Item = Artifact>>(iter: T) -> Self {
        let mut artifacts = Self::default();
        artifacts.extend(iter);
        artifacts
    }
}

impl IntoIterator for ArtifactSet {
    type Item = Artifact;
    type IntoIter = IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            inner: self.known.into_values().flatten().chain(self.unknown),
        }
    }
}

impl<'a> IntoIterator for &'a ArtifactSet {
    type Item = &'a Artifact;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'de> Deserialize<'de> for ArtifactSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ArtifactSet;

            fn expecting(
                &self,
                f: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                write!(f, "a sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<ArtifactSet, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                std::iter::from_fn(|| seq.next_element().transpose()).collect()
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

impl Serialize for ArtifactSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.iter())
    }
}

/// An iterator that moves values out of an [`ArtifactSet`].
///
/// This struct is created by [`ArtifactSet::into_iter`] (provided by the
/// [`IntoIterator`] trait).
#[derive(Debug)]
pub struct IntoIter {
    inner: Chain<
        Flatten<IntoValues<KnownArtifactTags, BTreeSet<Artifact>>>,
        btree_set::IntoIter<Artifact>,
    >,
}

impl Iterator for IntoIter {
    type Item = Artifact;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

/// An iterator that borrows values from an [`ArtifactSet`].
///
/// This struct is created by [`ArtifactSet::iter`].
#[derive(Debug, Clone)]
pub struct Iter<'a> {
    inner: Chain<
        Flatten<Values<'a, KnownArtifactTags, BTreeSet<Artifact>>>,
        btree_set::Iter<'a, Artifact>,
    >,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Artifact;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

/// Returned by [`ArtifactSet::get`] when there is not exactly one matching
/// artifact.
#[derive(Debug, thiserror::Error)]
pub enum GetError {
    #[error("artifact not found")]
    NotFound,
    #[error("more than one artifact found")]
    TooMany,
}
