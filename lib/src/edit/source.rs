// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::convert::Infallible;
use std::pin::Pin;

use bytes::Bytes;
use camino::Utf8PathBuf;
use futures_util::Stream;
use futures_util::StreamExt;
use futures_util::TryStreamExt;
use futures_util::stream;
use hubtools::Caboose;
use hubtools::RawHubrisArchive;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use tokio::fs::File;
use tokio::io::AsyncSeekExt;
use tokio_util::io::ReaderStream;
use tufaceous_artifact::ArtifactHash;

use crate::Repository;
use crate::error::Error;
use crate::error::ErrorKind;

#[derive(Debug)]
pub(crate) struct Target<'a> {
    pub(crate) length: u64,
    pub(crate) sha256: Vec<u8>,
    pub(crate) source: TargetSource<'a>,
}

#[derive(Debug)]
pub(crate) enum TargetSource<'a> {
    Bytes(BytesSource),
    File(FileSource),
    Repository(RepositorySource<'a>),
    Fake(FakeSource),
}

impl TargetSource<'_> {
    pub(crate) fn cost(&self) -> usize {
        match self {
            TargetSource::Bytes(_) => 0,
            TargetSource::Fake(_) => 1,
            TargetSource::File(_) => 2,
            TargetSource::Repository(_) => 3,
        }
    }

    pub(crate) fn stream(
        &mut self,
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes, Error>> + '_>> {
        match self {
            TargetSource::Bytes(BytesSource(bytes)) => {
                Box::pin(stream::once(std::future::ready(Ok(bytes.clone()))))
            }
            TargetSource::File(source) => Box::pin(source.stream()),
            TargetSource::Repository(source) => Box::pin(source.stream()),
            TargetSource::Fake(source) => {
                Box::pin(source.stream().err_into::<Error>())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BytesSource(pub(crate) Bytes);

impl BytesSource {
    pub(crate) fn json<T: Serialize>(
        data: &T,
    ) -> Result<Self, serde_json::Error> {
        let mut s = serde_json::to_string_pretty(data)?;
        s.push('\n');
        Ok(Self(s.into()))
    }

    pub(crate) fn into_target(self) -> Target<'static> {
        Target {
            length: self.0.len().try_into().unwrap(),
            sha256: Sha256::digest(&self.0).to_vec(),
            source: TargetSource::Bytes(self),
        }
    }
}

#[derive(Debug)]
pub(crate) struct FileSource {
    file: File,
    pub(crate) path: Utf8PathBuf,
    length_sha256: Option<(u64, ArtifactHash)>,
}

impl FileSource {
    pub(crate) async fn open(path: Utf8PathBuf) -> Result<Self, Error> {
        let file = File::open(&path).await.map_err(|source| {
            ErrorKind::OpenFile { source, path: path.clone() }
        })?;
        Ok(Self::from_file(file, path))
    }

    pub(crate) fn from_file(file: File, path: Utf8PathBuf) -> Self {
        Self { file, path, length_sha256: None }
    }

    pub(crate) async fn into_target(
        mut self,
    ) -> Result<Target<'static>, Error> {
        let (length, sha256) = match self.length_sha256 {
            Some(inner) => inner,
            None => self.read_impl(None).await?,
        };
        Ok(Target {
            length,
            sha256: sha256.0.to_vec(),
            source: TargetSource::File(self),
        })
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
                    length += u64::try_from(bytes.len()).unwrap();
                    hasher.update(&bytes);
                    if let Some(vec) = vec.as_mut() {
                        vec.extend_from_slice(&bytes)
                    }
                    std::future::ready(Ok((length, hasher)))
                },
            )
            .await?;
        let sha256 = ArtifactHash(hasher.finalize().into());
        Ok(*self.length_sha256.insert((length, sha256)))
    }

    pub(crate) async fn sha256(&mut self) -> Result<ArtifactHash, Error> {
        let (_, sha256) = match self.length_sha256 {
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
        RawHubrisArchive::from_vec(self.read_to_end().await?).map_err(
            |source| {
                ErrorKind::ReadHubrisArchive { source, path: self.path.clone() }
                    .into()
            },
        )
    }

    pub(crate) async fn read_hubris_caboose(
        &mut self,
    ) -> Result<Caboose, Error> {
        self.read_hubris_archive().await?.read_caboose().map_err(|source| {
            ErrorKind::ReadHubrisArchive { source, path: self.path.clone() }
                .into()
        })
    }

    pub(crate) fn stream(
        &mut self,
    ) -> impl Stream<Item = Result<Bytes, Error>> {
        stream::once(async {
            if let Err(source) = self.file.rewind().await {
                return Err(Error::from(ErrorKind::SeekFile {
                    source,
                    path: self.path.clone(),
                }));
            }
            Ok(ReaderStream::new(&mut self.file)
                .map_err(|source| ErrorKind::ReadFile {
                    source,
                    path: self.path.clone(),
                })
                .err_into::<Error>())
        })
        .try_flatten()
    }
}

#[derive(Debug)]
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
            source: TargetSource::Repository(self),
        }
    }

    pub(crate) fn stream(&self) -> impl Stream<Item = Result<Bytes, Error>> {
        stream::once(self.repo.read_target(&self.target_name)).try_flatten()
    }
}

#[derive(Debug)]
pub(crate) struct FakeSource {
    prefix: Bytes,
    length: usize,
    sha256: Option<ArtifactHash>,
}

impl FakeSource {
    pub(crate) fn new(prefix: String, length: usize) -> Self {
        Self { prefix: prefix.into(), length, sha256: None }
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
            length: self.length.try_into().unwrap(),
            sha256: self.sha256().await.0.to_vec(),
            source: TargetSource::Fake(self),
        }
    }

    pub(crate) fn stream(
        &self,
    ) -> impl Stream<Item = Result<Bytes, Infallible>> + 'static {
        const ZERO: Bytes = Bytes::from_static(&[0; 8192]);

        let mut prefix = self.prefix.clone();
        prefix.truncate(self.length);
        let suffix = stream::unfold(
            self.length.saturating_sub(prefix.len()),
            |remaining| {
                std::future::ready(if remaining == 0 {
                    None
                } else if remaining < ZERO.len() {
                    Some((Ok(ZERO.slice(..remaining)), 0))
                } else {
                    Some((Ok(ZERO), remaining - ZERO.len()))
                })
            },
        );
        stream::once(std::future::ready(Ok(prefix))).chain(suffix)
    }
}
