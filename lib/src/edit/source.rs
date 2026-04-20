// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
    pub(crate) sha256: Vec<u8>,
    pub(crate) source: TargetSource<'a>,
}

#[derive(Debug, Clone)]
pub(crate) enum TargetSource<'a> {
    Bytes(BytesSource),
    File(FileSource),
    Repository(RepositorySource<'a>),
}

impl TargetSource<'_> {
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
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes, Error>> + '_>> {
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
                length - u64::try_from(bytes.len()).expect("usize fits in u64")
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
        self.fake_length.unwrap_or_else(|| {
            self.bytes.len().try_into().expect("usize fits in u64")
        })
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
        *self.sha256.insert(ArtifactHash(hasher.finalize().into()))
    }

    pub(crate) async fn into_target(mut self) -> Target<'static> {
        Target {
            length: self.length(),
            sha256: self.sha256().await.0.to_vec(),
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
        Ok(Target { length, sha256: sha256.0.to_vec(), source: self.into() })
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
                    length +=
                        u64::try_from(bytes.len()).expect("usize fits in u64");
                    hasher.update(&bytes);
                    if let Some(vec) = vec.as_mut() {
                        vec.extend_from_slice(&bytes);
                    }
                    std::future::ready(Ok((length, hasher)))
                },
            )
            .await?;
        let sha256 = ArtifactHash(hasher.finalize().into());
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
        stream::try_unfold(
            (self.inner.clone(), BytesMut::new(), 0),
            async |(inner, mut buf, mut offset)| {
                tokio::task::spawn_blocking(move || {
                    if buf.capacity() == 0 {
                        buf.reserve(8192);
                    }
                    buf.resize(buf.capacity(), 0);
                    let n = try_path!(
                        inner.file.read_at(&mut buf, offset),
                        ReadFile,
                        inner.path.clone()
                    );
                    if n == 0 {
                        return Ok(None);
                    }
                    offset += u64::try_from(n).expect("usize fits in u64");
                    buf.truncate(n);
                    Ok(Some((buf.split().freeze(), (inner, buf, offset))))
                })
                .await?
            },
        )
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
    pub(crate) fn into_target(self) -> Target<'a> {
        Target {
            length: self.length,
            sha256: self.sha256.clone(),
            source: self.into(),
        }
    }

    pub(crate) fn stream(&self) -> impl Stream<Item = Result<Bytes, Error>> {
        stream::once(self.repo.read_target(&self.target_name)).try_flatten()
    }
}
