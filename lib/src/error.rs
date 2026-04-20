// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::error::Error as _;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::ops::Deref;
use std::ops::Range;

use crate::ZipTransportError;
use camino::Utf8PathBuf;
use tough::TransportErrorKind;

macro_rules! try_path {
    ($result:expr, $kind:ident, $path:expr) => {
        match $result {
            Ok(value) => value,
            Err(source) => {
                return Err(
                    ErrorKind::$kind { source, path: $path.into() }.into()
                )
            }
        }
    };
}
pub(crate) use try_path;
use tufaceous_artifact::DisplayTags;

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Error(pub Box<ErrorKind>);

impl Deref for Error {
    type Target = ErrorKind;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    #[error(transparent)]
    Fetch(tough::TransportError),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
    #[error(transparent)]
    Tough(tough::error::Error),
    #[error("error while manipulating key")]
    ToughKey(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error(
        "failed to read zip archive{archive_path}",
        archive_path = SpacePath(archive_path),
    )]
    ReadZip { source: rawzip::Error, archive_path: Option<Utf8PathBuf> },
    #[error(
        "failed to write zip archive{archive_path}",
        archive_path = SpacePath(archive_path),
    )]
    WriteZip { source: rawzip::Error, archive_path: Option<Utf8PathBuf> },
    #[error(
        "zip archive{archive_path}'s end of central directory record \
        expects {expected} entries, but found {actual} entries",
        archive_path = SpacePath(archive_path)
    )]
    ZipEntryCount {
        expected: u64,
        actual: u64,
        archive_path: Option<Utf8PathBuf>,
    },
    #[error(
        "zip archive{archive_path} has overlapping compressed data ranges: \
        {earlier_path:?} ({earlier:?}) and {later_path:?} ({later:?})",
        archive_path = SpacePath(archive_path),
        earlier_path = DebugByteString(earlier_path),
        later_path = DebugByteString(later_path),
    )]
    ZipOverlappingRanges {
        earlier_path: Vec<u8>,
        earlier: Range<u64>,
        later_path: Vec<u8>,
        later: Range<u64>,
        archive_path: Option<Utf8PathBuf>,
    },
    #[error(
        "zip archive{archive_path} path name mismatch between central directory \
        and local header ({central:?} != {local:?})",
        archive_path = SpacePath(archive_path),
        central = DebugByteString(central),
        local = DebugByteString(local),
    )]
    ZipPathMismatch {
        central: Vec<u8>,
        local: Vec<u8>,
        archive_path: Option<Utf8PathBuf>,
    },
    #[error(
        "zip archive{archive_path} compressed data range for {file_path:?} \
        ({data_range:?}) overruns central directory",
        archive_path = SpacePath(archive_path),
        file_path = DebugByteString(file_path),
    )]
    ZipRangeOverrun {
        file_path: Vec<u8>,
        data_range: Range<u64>,
        archive_path: Option<Utf8PathBuf>,
    },

    #[error("failed to create temporary directory")]
    CreateTempDir(#[source] std::io::Error),
    #[error("failed to create temporary file")]
    CreateTempFile(#[source] std::io::Error),
    #[error("failed to open file{path}", path = SpacePath(path))]
    OpenFile { source: std::io::Error, path: Option<Utf8PathBuf> },
    #[error("failed to read directory{path}", path = SpacePath(path))]
    ReadDir { source: std::io::Error, path: Option<Utf8PathBuf> },
    #[error("failed to read from file{path}", path = SpacePath(path))]
    ReadFile { source: std::io::Error, path: Option<Utf8PathBuf> },
    #[error("failed to seek in file{path}", path = SpacePath(path))]
    SeekFile { source: std::io::Error, path: Option<Utf8PathBuf> },
    #[error("failed to write to file{path}", path = SpacePath(path))]
    WriteFile { source: std::io::Error, path: Option<Utf8PathBuf> },
    #[error("failed to read stream")]
    ReadStream(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("stream exceeded length limit ({limit})")]
    StreamLimit { limit: u64 },

    #[error("failed to read hubris archive {path}")]
    ReadHubrisArchive { source: hubtools::Error, path: Utf8PathBuf },
    #[error("failed to read caboose from {path}")]
    ReadCaboose {
        source: tufaceous_artifact::ReadCabooseError,
        path: Utf8PathBuf,
    },
    #[error("failed to generate fake hubris archive")]
    GenerateFakeHubrisArchive(#[source] hubtools::Error),
    #[error("failed to read CoRIM manifest {path}")]
    ReadCorim { source: rats_corim::Error, path: Utf8PathBuf },
    #[error("failed to generate fake measurement corpus")]
    GenerateFakeMeasurementCorpus(#[source] rats_corim::Error),
    #[error("failed to serialize fake measurement corpus")]
    SerializeFakeMeasurementCorpus(#[source] rats_corim::Error),
    #[error("failed to generate fake zone image")]
    GenerateFakeZoneImage(#[source] std::io::Error),

    #[error("unspecified failure when generating ed25519 key")]
    Ed25519Generate,
    #[error("failed to calculate TUF key ID")]
    KeyId(#[source] tough::schema::Error),
    #[error("failed to serialize root role")]
    SerializeRoot(#[source] serde_json::Error),
    #[error("role verification failed")]
    RoleVerify(#[source] tough::schema::Error),

    #[error("metadata base URL unset")]
    MetadataBaseUrlUnset,
    #[error("targets base URL unset")]
    TargetsBaseUrlUnset,
    #[error("failed to join {url} onto {base}")]
    UrlJoin { source: url::ParseError, url: &'static str, base: String },
    #[error("no trust roots provided to load repository")]
    NoTrustRoots,
    #[error("target {target_name} not found")]
    TargetNotFound { target_name: String },
    #[error("failed to parse target {target}")]
    ParseTargetJson { source: serde_json::Error, target: String },

    #[error(transparent)]
    ArtifactVersion(#[from] tufaceous_artifact::ArtifactVersionError),
    #[error("failed to guess what kind of artifact {path} is")]
    GuessArtifact { path: Utf8PathBuf },
    #[error("target name collision on {target_name}")]
    TargetNameCollision { target_name: String },
    #[error(
        "artifacts {first_target_name} and {second_target_name}
        have the same tags {tags}, which is not allowed",
        tags = DisplayTags::from(.tags),
    )]
    DisallowedTagCollision {
        first_target_name: String,
        second_target_name: String,
        tags: BTreeMap<String, String>,
    },
    #[error("failed to serialize artifacts document")]
    SerializeArtifacts(#[source] serde_json::Error),
    #[error("failed to serialize Installinator document")]
    SerializeInstallinator(#[source] serde_json::Error),
    #[error("no root provided to sign repository")]
    NoSigningRoot,
    #[error("failed to parse signing root")]
    ParseSigningRoot(#[source] serde_json::Error),

    #[error("failed to read composite artifact {target}")]
    ReadCompositeArtifact { source: std::io::Error, target: String },
    #[error("failed to read oxide.json from {path}")]
    ReadZoneOxideJson { source: std::io::Error, path: Utf8PathBuf },
    #[error("importing v1 repository to an editor is not supported")]
    ImportV1Repo,
}

impl ErrorKind {
    /// Returns `true` if the error is due to a problem loading or reading
    /// a repository, where retrying the operation with the same input would
    /// result in the same error.
    ///
    /// Note that errors that can return `true` here can also happen during
    /// other operations, such as editing or signing repositories.
    pub fn is_repository_error(&self) -> bool {
        match self {
            ErrorKind::ZipEntryCount { .. }
            | ErrorKind::ZipOverlappingRanges { .. }
            | ErrorKind::ZipPathMismatch { .. }
            | ErrorKind::ZipRangeOverrun { .. }
            | ErrorKind::StreamLimit { .. }
            | ErrorKind::ReadHubrisArchive { .. }
            | ErrorKind::ReadCaboose { .. }
            | ErrorKind::MetadataBaseUrlUnset
            | ErrorKind::TargetsBaseUrlUnset
            | ErrorKind::UrlJoin { .. }
            | ErrorKind::NoTrustRoots
            | ErrorKind::TargetNotFound { .. }
            | ErrorKind::ParseTargetJson { .. }
            | ErrorKind::ArtifactVersion(_)
            | ErrorKind::ReadCompositeArtifact { .. }
            | ErrorKind::ReadZoneOxideJson { .. } => true,

            ErrorKind::Join(_)
            | ErrorKind::ToughKey(_)
            | ErrorKind::WriteZip { .. }
            | ErrorKind::CreateTempDir(_)
            | ErrorKind::CreateTempFile(_)
            | ErrorKind::OpenFile { .. }
            | ErrorKind::ReadDir { .. }
            | ErrorKind::ReadFile { .. }
            | ErrorKind::SeekFile { .. }
            | ErrorKind::WriteFile { .. }
            | ErrorKind::ReadStream(_)
            | ErrorKind::GenerateFakeHubrisArchive(_)
            | ErrorKind::GenerateFakeMeasurementCorpus(_)
            | ErrorKind::ReadCorim { .. }
            | ErrorKind::SerializeFakeMeasurementCorpus(_)
            | ErrorKind::GenerateFakeZoneImage(_)
            | ErrorKind::Ed25519Generate
            | ErrorKind::KeyId(_)
            | ErrorKind::SerializeRoot(_)
            | ErrorKind::RoleVerify(_)
            | ErrorKind::GuessArtifact { .. }
            | ErrorKind::TargetNameCollision { .. }
            | ErrorKind::DisallowedTagCollision { .. }
            | ErrorKind::SerializeArtifacts(_)
            | ErrorKind::SerializeInstallinator(_)
            | ErrorKind::NoSigningRoot
            | ErrorKind::ParseSigningRoot(_)
            | ErrorKind::ImportV1Repo => false,

            ErrorKind::Fetch(error) => {
                // A transport error might be due to a broken repository (e.g.
                // HTTP Not Found, ZIP CRC mismatch), but it might also be due
                // to a retryable problem (e.g. HTTP timeout). We will try and
                // classify errors we can introspect but otherwise we'll return
                // false.
                match error.kind() {
                    TransportErrorKind::UnsupportedUrlScheme
                    | TransportErrorKind::FileNotFound => return true,
                    _ => {}
                }
                if let Some(source) = error.source().and_then(|source| {
                    source.downcast_ref::<ZipTransportError>()
                }) {
                    return match source {
                        ZipTransportError::UrlJoin { .. }
                        | ZipTransportError::CompressionMethod(_)
                        | ZipTransportError::Duplicate
                        | ZipTransportError::FileNotFound
                        | ZipTransportError::IsADirectory
                        | ZipTransportError::IsASymlink => true,

                        ZipTransportError::Io(_)
                        | ZipTransportError::Join(_) => false,

                        ZipTransportError::Zip(source) => {
                            // All of rawzip's errors are related to broken zip
                            // files, except for IO errors.
                            !matches!(source.kind(), rawzip::ErrorKind::IO(_))
                        }
                    };
                }
                false
            }

            ErrorKind::Tough(error) => {
                // tough's errors are... tough to classify. We have a pretty
                // simple heuristic: if any error in the source chain is
                // `std::io::Error`, return false. Otherwise, return true.
                for source in std::iter::successors(error.source(), |source| {
                    (*source).source()
                }) {
                    if source.downcast_ref::<std::io::Error>().is_some() {
                        return false;
                    }
                }
                true
            }

            ErrorKind::ReadZip { source, .. } => {
                // All of rawzip's errors are related to broken zip files,
                // except for IO errors.
                !matches!(source.kind(), rawzip::ErrorKind::IO(_))
            }
        }
    }
}

impl<T: Into<ErrorKind>> From<T> for Error {
    fn from(kind: T) -> Self {
        Error(Box::new(kind.into()))
    }
}

impl From<tough::error::Error> for ErrorKind {
    fn from(error: tough::error::Error) -> Self {
        if let tough::error::Error::Transport { source, .. } = error {
            ErrorKind::Fetch(source)
        } else {
            ErrorKind::Tough(error)
        }
    }
}

impl From<Infallible> for ErrorKind {
    fn from(error: Infallible) -> Self {
        match error {}
    }
}

struct SpacePath<'a>(&'a Option<Utf8PathBuf>);

impl Display for SpacePath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(path) => write!(f, " {path}"),
            None => Ok(()),
        }
    }
}

pub(crate) struct DebugByteString<'a>(pub(crate) &'a [u8]);

impl Debug for DebugByteString<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(s) = std::str::from_utf8(self.0) {
            write!(f, "{s:?}")
        } else {
            write!(f, "b\"{}\"", self.0.escape_ascii())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;
    use std::fmt::Write;

    use crate::error::Error;
    use crate::error::ErrorKind;

    #[test]
    fn error_display_chain_doesnt_repeat() {
        let err = Error::from(ErrorKind::OpenFile {
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
            path: Some("/nowhere/in/particular".into()),
        });
        let mut chain = err.to_string();
        let mut source = err.source();
        while let Some(err) = source {
            write!(chain, ": {err}").unwrap();
            source = err.source();
        }

        assert_eq!(
            chain,
            "failed to open file /nowhere/in/particular: entity not found"
        );
    }
}
