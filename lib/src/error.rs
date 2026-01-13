// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::convert::Infallible;
use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::ops::Range;

use camino::Utf8PathBuf;

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Error(pub Box<ErrorKind>);

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    #[error(transparent)]
    Fetch(tough::TransportError),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
    #[error(transparent)]
    Tough(#[from] tough::error::Error),
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
        source: tufaceous_artifact::hubris::ReadCabooseError,
        path: Utf8PathBuf,
    },

    #[error("unspecified failure when generating ed25519 key")]
    Ed25519Generate,
    #[error("failed to calculate TUF key ID")]
    KeyId(#[source] tough::schema::Error),

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
    #[error("failed to read {path} as CoRIM")]
    Corim { source: ciborium::de::Error<std::io::Error>, path: Utf8PathBuf },
    #[error("failed to guess what kind of artifact {path} is")]
    GuessArtifact { path: Utf8PathBuf },
    #[error("target name collision on {target_name}")]
    TargetNameCollision { target_name: String },
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

impl<T: Into<ErrorKind>> From<T> for Error {
    fn from(kind: T) -> Self {
        Error(Box::new(kind.into()))
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

struct DebugByteString<'a>(&'a [u8]);

impl Debug for DebugByteString<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(s) = std::str::from_utf8(self.0) {
            write!(f, "{s:?}")
        } else {
            write!(f, "b\"{}\"", self.0.escape_ascii())
        }
    }
}

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
