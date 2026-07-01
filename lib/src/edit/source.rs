// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Indirection layer for reading target data from varying sources.
//!
//! When generating a repository, the data for each target could come from
//! one of several places. In the normal case it comes from a file on disk
//! ([`FileSource`]). If it is particularly small or is fake it might be an
//! in-memory representation ([`BytesSource`]). If we're editing an existing
//! repository, all of the previous repository's artifacts are treated as a
//! pointer to the open repository ([`RepositorySource`]).
//!
//! [`TargetSource`] is an enum that covers all three of these possible sources,
//! and has static dispatch for reading the underlying source as a `Stream`.
//!
//! Each of the three concrete sources has an `into_target` method which returns
//! a [`Target`], which is the `TargetSource` along with the target's length and
//! SHA-256 checksum.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use bytes::Bytes;
use bytes::BytesMut;
use camino::Utf8Path;
use camino::Utf8PathBuf;
use futures_util::Stream;
use futures_util::StreamExt;
use futures_util::TryStreamExt;
use futures_util::stream;
use hubtools::Caboose;
use hubtools::RawHubrisArchive;
use rawzip::FileReader;
use rawzip::ReaderAt;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use tokio::fs::File;
use tufaceous_artifact::ArtifactHash;

use crate::Repository;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::error::try_path;

#[derive(Debug)]
pub(crate) struct Target<'a> {
    pub(crate) length: u64,
    pub(crate) sha256: ArtifactHash,
    pub(crate) source: TargetSource<'a>,
}

#[derive(Debug, Clone)]
pub(crate) enum TargetSource<'a> {
    Bytes(BytesSource),
    File(FileSource),
    Repository(RepositorySource<'a>),
}

impl TargetSource<'_> {
    /// A relative indication of how computationally expensive it is to read
    /// from this source, given two sources of the data.
    ///
    /// For example, reading from a file on disk is preferred from reading a
    /// target out of an opened repository.
    pub(crate) fn cost(&self) -> usize {
        match self {
            TargetSource::Bytes(BytesSource { fake_length: None, .. }) => 0,
            TargetSource::Bytes(_) => 1,
            TargetSource::File(_) => 2,
            TargetSource::Repository(_) => 3,
        }
    }

    pub(crate) fn stream(
        &self,
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes, Error>> + Send + '_>> {
        match self {
            TargetSource::Bytes(source) => {
                Box::pin(source.stream().err_into::<Error>())
            }
            TargetSource::File(source) => Box::pin(source.stream()),
            TargetSource::Repository(source) => Box::pin(source.stream()),
        }
    }
}

impl From<BytesSource> for TargetSource<'_> {
    fn from(source: BytesSource) -> Self {
        TargetSource::Bytes(source)
    }
}

impl From<FileSource> for TargetSource<'_> {
    fn from(source: FileSource) -> Self {
        TargetSource::File(source)
    }
}

impl<'a> From<RepositorySource<'a>> for TargetSource<'a> {
    fn from(source: RepositorySource<'a>) -> Self {
        TargetSource::Repository(source)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BytesSource {
    bytes: Bytes,
    fake_length: Option<u64>,
    sha256: Option<ArtifactHash>,
}

impl BytesSource {
    pub(crate) fn new(bytes: impl Into<Bytes>) -> Self {
        Self { bytes: bytes.into(), fake_length: None, sha256: None }
    }

    pub(crate) fn json<T: Serialize>(
        data: &T,
    ) -> Result<Self, serde_json::Error> {
        let mut s = serde_json::to_string_pretty(data)?;
        s.push('\n');
        Ok(Self { bytes: s.into(), fake_length: None, sha256: None })
    }

    pub(crate) fn fake_padded(prefix: impl Into<Bytes>, length: u64) -> Self {
        Self { bytes: prefix.into(), fake_length: Some(length), sha256: None }
    }

    pub(crate) fn iter_bytes(&self) -> impl Iterator<Item = Bytes> + 'static {
        let mut bytes = self.bytes.clone();
        let mut remaining = match self.fake_length {
            Some(length) => {
                if let Ok(length) = usize::try_from(length) {
                    bytes.truncate(length);
                }
                length - usize64!(bytes.len())
            }
            None => 0,
        };
        std::iter::once(bytes).chain(std::iter::from_fn(move || {
            static ZERO: &[u8] = &[0; 8192];
            if remaining == 0 {
                None
            } else {
                let end = remaining.min(8192);
                remaining -= end;
                let end = usize::try_from(end).expect("8192 <= usize::MAX");
                Some(Bytes::from_static(&ZERO[..end]))
            }
        }))
    }

    pub(crate) fn stream(
        &self,
    ) -> impl Stream<Item = Result<Bytes, Infallible>> + 'static {
        stream::iter(self.iter_bytes().map(Ok))
    }

    pub(crate) fn length(&self) -> u64 {
        self.fake_length.unwrap_or_else(|| usize64!(self.bytes.len()))
    }

    async fn sha256(&mut self) -> ArtifactHash {
        if let Some(sha256) = self.sha256 {
            return sha256;
        }
        let mut stream = self.stream();
        let mut hasher = Sha256::new();
        while let Some(Ok(bytes)) = stream.next().await {
            hasher.update(&bytes);
        }
        *self.sha256.insert(ArtifactHash(hasher.finalize().0))
    }

    pub(crate) async fn into_target(mut self) -> Target<'static> {
        Target {
            length: self.length(),
            sha256: self.sha256().await,
            source: self.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FileSource {
    inner: Arc<FileSourceInner>,
}

#[derive(Debug)]
struct FileSourceInner {
    file: FileReader,
    path: Utf8PathBuf,
    length_sha256: Mutex<Option<(u64, ArtifactHash)>>,
}

impl FileSource {
    pub(crate) async fn open(path: Utf8PathBuf) -> Result<Self, Error> {
        let file = try_path!(File::open(&path).await, OpenFile, path);
        Ok(Self::from_file(file.into_std().await, path))
    }

    pub(crate) async fn try_open(
        path: Utf8PathBuf,
    ) -> Result<Option<Self>, Error> {
        let file = match File::open(&path).await {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(err) => try_path!(Err(err), OpenFile, path),
        };
        Ok(Some(Self::from_file(file.into_std().await, path)))
    }

    pub(crate) fn from_file(file: std::fs::File, path: Utf8PathBuf) -> Self {
        Self {
            inner: Arc::new(FileSourceInner {
                file: file.into(),
                path,
                length_sha256: Mutex::new(None),
            }),
        }
    }

    pub(crate) fn path(&self) -> &Utf8Path {
        &self.inner.path
    }

    pub(crate) async fn into_target(
        mut self,
    ) -> Result<Target<'static>, Error> {
        let inner = {
            let guard = self.inner.length_sha256.lock().expect("poisoned");
            *guard
        };
        let (length, sha256) = match inner {
            Some(inner) => inner,
            None => self.read_impl(None).await?,
        };
        Ok(Target { length, sha256, source: self.into() })
    }

    async fn read_impl(
        &mut self,
        mut vec: Option<&mut Vec<u8>>,
    ) -> Result<(u64, ArtifactHash), Error> {
        let (length, hasher) = self
            .stream()
            .try_fold(
                (0u64, Sha256::new()),
                |(mut length, mut hasher), bytes| {
                    length += usize64!(bytes.len());
                    hasher.update(&bytes);
                    if let Some(vec) = vec.as_mut() {
                        vec.extend_from_slice(&bytes);
                    }
                    std::future::ready(Ok((length, hasher)))
                },
            )
            .await?;
        let sha256 = ArtifactHash(hasher.finalize().0);
        Ok({
            let mut guard = self.inner.length_sha256.lock().expect("poisoned");
            *guard.insert((length, sha256))
        })
    }

    pub(crate) async fn sha256(&mut self) -> Result<ArtifactHash, Error> {
        let inner = {
            let guard = self.inner.length_sha256.lock().expect("poisoned");
            *guard
        };
        let (_, sha256) = match inner {
            Some(inner) => inner,
            None => self.read_impl(None).await?,
        };
        Ok(sha256)
    }

    pub(crate) async fn read_to_end(&mut self) -> Result<Vec<u8>, Error> {
        let mut vec = Vec::new();
        self.read_impl(Some(&mut vec)).await?;
        Ok(vec)
    }

    pub(crate) async fn read_hubris_archive(
        &mut self,
    ) -> Result<RawHubrisArchive, Error> {
        Ok(try_path!(
            RawHubrisArchive::from_vec(self.read_to_end().await?),
            ReadHubrisArchive,
            &self.inner.path
        ))
    }

    pub(crate) async fn read_hubris_caboose(
        &mut self,
    ) -> Result<Caboose, Error> {
        Ok(try_path!(
            self.read_hubris_archive().await?.read_caboose(),
            ReadHubrisArchive,
            &self.inner.path
        ))
    }

    pub(crate) fn stream(&self) -> impl Stream<Item = Result<Bytes, Error>> {
        let inner = self.inner.clone();
        crate::mpsc_stream::mpsc_stream(None, move |tx| {
            let mut buf = BytesMut::with_capacity(8192);
            let mut offset = 0;
            loop {
                if buf.capacity() == 0 {
                    buf.reserve(8192);
                }
                buf.resize(buf.capacity(), 0);
                match inner.file.read_at(&mut buf, offset) {
                    Ok(n) => {
                        buf.truncate(n);
                    }
                    Err(source) => {
                        let err = ErrorKind::ReadFile {
                            source,
                            path: Some(inner.path.clone()),
                        };
                        return tx.blocking_send(Err(err.into()));
                    }
                }

                let bytes = buf.split().freeze();
                if bytes.is_empty() {
                    return Ok(());
                }
                offset += usize64!(bytes.len());
                tx.blocking_send(Ok(bytes))?;
            }
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RepositorySource<'a> {
    pub(crate) repo: &'a Repository,
    pub(crate) target_name: String,
    pub(crate) length: u64,
    pub(crate) sha256: Vec<u8>,
}

impl<'a> RepositorySource<'a> {
    pub(crate) fn into_target(self) -> Result<Target<'a>, Error> {
        let sha256 = match self.sha256.as_slice().try_into() {
            Ok(sha256) => ArtifactHash(sha256),
            Err(_) => {
                return Err(ErrorKind::InvalidHashLength {
                    target_name: self.target_name,
                }
                .into());
            }
        };
        Ok(Target { length: self.length, sha256, source: self.into() })
    }

    pub(crate) fn stream(&self) -> impl Stream<Item = Result<Bytes, Error>> {
        stream::once(self.repo.read_target(&self.target_name)).try_flatten()
    }
}
