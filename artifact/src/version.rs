// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{borrow::Cow, fmt, str::FromStr};

use daft::Diffable;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An artifact version.
///
/// This is a freeform identifier with some basic validation. It may be the
/// serialized form of a semver version, or a custom identifier that uses the
/// same character set as a semver.
///
/// For the exact regex pattern accepted by [`ArtifactVersion::new`], see
/// [`ArtifactVersion::REGEX`].
///
/// # Ord implementation
///
/// `ArtifactVersion`s are not intended to be sorted, just compared for
/// equality. `ArtifactVersion` implements `Ord` only for storage within sorted
/// collections.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Diffable)]
#[cfg_attr(any(test, feature = "proptest"), derive(test_strategy::Arbitrary))]
#[cfg_attr(any(test, feature = "schemars"), derive(schemars::JsonSchema))]
#[cfg_attr(any(test, feature = "schemars"), schemars(regex = Self::REGEX))]
#[daft(leaf)]
pub struct ArtifactVersion(
    #[cfg_attr(any(test, feature = "proptest"), strategy(PROPTEST_REGEX))]
    #[cfg_attr(any(test, feature = "proptest"), map(Cow::Owned))]
    #[cfg_attr(
        any(test, feature = "schemars"),
        schemars(regex = "Self::REGEX")
    )]
    Cow<'static, str>,
);

impl ArtifactVersion {
    /// The maximum length of a version string.
    ///
    /// This matches the length allowed in Omicron database storage.
    pub const MAX_LEN: usize = 63;

    /// A regular expression that matches a valid version string.
    ///
    /// This is the set of characters allowed in a semver, though without any
    /// additional structure. We expect non-semver identifiers to only use these
    /// characters as well.
    pub const REGEX: &str = r"^[a-zA-Z0-9._+-]{1,63}$";

    /// Constructs a new `ArtifactVersion` from a static string.
    pub const fn new_static(
        version: &'static str,
    ) -> Result<Self, ArtifactVersionError> {
        // Can't use `?` in const functions.
        match validate_version(version) {
            Ok(()) => Ok(Self(Cow::Borrowed(version))),
            Err(err) => Err(err),
        }
    }

    /// Constructs a new `ArtifactVersion` from a string.
    pub fn new<S: Into<String>>(
        version: S,
    ) -> Result<Self, ArtifactVersionError> {
        let version = version.into();

        validate_version(&version)?;

        Ok(Self(Cow::Owned(version)))
    }

    /// Returns the version as a string.
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    /// Consumes self, returning the version as a string.
    pub fn into_inner(self) -> Cow<'static, str> {
        self.0
    }
}

impl FromStr for ArtifactVersion {
    type Err = ArtifactVersionError;

    #[inline]
    fn from_str(version: &str) -> Result<Self, Self::Err> {
        Self::new(version)
    }
}

impl fmt::Display for ArtifactVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ArtifactVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let version = String::deserialize(deserializer)?;
        validate_version(&version).map_err(serde::de::Error::custom)?;

        Ok(Self(Cow::Owned(version)))
    }
}

impl Serialize for ArtifactVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

const fn validate_version(version: &str) -> Result<(), ArtifactVersionError> {
    let len = version.len();

    if len == 0 {
        return Err(ArtifactVersionError::Empty);
    } else if len > ArtifactVersion::MAX_LEN {
        return Err(ArtifactVersionError::TooLong { len });
    }

    // Check that the version string matches the regex.
    let mut b = version.as_bytes();
    while let [first, rest @ ..] = b {
        if !first.is_ascii_alphanumeric()
            && !matches!(first, b'.' | b'_' | b'+' | b'-')
        {
            return Err(ArtifactVersionError::InvalidCharacter);
        }
        b = rest;
    }

    Ok(())
}

// Proptest wants regexes without anchors, so drop the first and last
// character.
#[cfg(any(test, feature = "proptest"))]
static PROPTEST_REGEX: &str = {
    let regex = ArtifactVersion::REGEX.as_bytes();
    let [_, mid @ .., _] = regex else { unreachable!() };
    let Ok(r) = std::str::from_utf8(mid) else { unreachable!() };
    r
};

/// An error that occurred while creating an `ArtifactVersion`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ArtifactVersionError {
    #[error("version is empty")]
    Empty,
    #[error(
        "version is too long ({len} bytes, max {})",
        ArtifactVersion::MAX_LEN
    )]
    TooLong { len: usize },
    #[error(
        "version contains invalid character (allowed: {})",
        ArtifactVersion::REGEX
    )]
    InvalidCharacter,
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use super::*;
    use regex::Regex;
    use schemars::schema_for;
    use test_strategy::proptest;

    #[test]
    fn schema() {
        let schema = schema_for!(ArtifactVersion);
        expectorate::assert_contents(
            "output/artifact_version_schema.json",
            &serde_json::to_string_pretty(&schema).unwrap(),
        );
    }

    #[proptest]
    fn proptest_valid_version(#[strategy(PROPTEST_REGEX)] version: String) {
        validate_version(&version).unwrap();
    }

    #[proptest]
    fn proptest_version_serde_roundtrip(version: ArtifactVersion) {
        let json = serde_json::to_string(&version).unwrap();

        // Try deserializing as a string -- this should always work (and ensures that version looks like a string in JSON).
        serde_json::from_str::<String>(&json)
            .expect("deserialized version as a string");

        let deserialized = serde_json::from_str(&json).unwrap();
        assert_eq!(version, deserialized);
    }

    #[proptest]
    fn proptest_invalid_version(#[filter(is_invalid_regex)] version: String) {
        validate_version(&version).unwrap_err();
    }

    // expect(clippy::ptr_arg) is because `filter` doesn't accept &str, just &String.
    fn is_invalid_regex(#[expect(clippy::ptr_arg)] version: &String) -> bool {
        static REGEX: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(ArtifactVersion::REGEX).unwrap());
        !REGEX.is_match(version)
    }
}
