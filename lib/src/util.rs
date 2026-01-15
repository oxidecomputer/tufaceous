// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::io::Read;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use camino::FromPathBufError;
use camino::Utf8Path;
use camino::Utf8PathBuf;
use flate2::read::GzDecoder;
use futures_util::Stream;
use tufaceous_brand_metadata::LayerInfo;
use tufaceous_brand_metadata::Metadata;

use crate::error::Error;
use crate::error::ErrorKind;
use crate::error::try_path;

pub(crate) async fn read_zone_layer_info<R: Read + Send + 'static>(
    reader: R,
    path: Utf8PathBuf,
) -> Result<(R, LayerInfo), Error> {
    tokio::task::spawn_blocking(move || {
        let mut archive = tar::Archive::new(GzDecoder::new(reader));
        let layer_info = Metadata::read_from_tar(&mut archive)
            .and_then(|metadata| metadata.layer_info().cloned())
            .map_err(|source| ErrorKind::ReadZoneOxideJson { source, path })?;
        Ok((archive.into_inner().into_inner(), layer_info))
    })
    .await?
}

pub(crate) async fn read_dir(path: Utf8PathBuf) -> Result<ReadDir, Error> {
    let inner = try_path!(tokio::fs::read_dir(&path).await, ReadDir, path);
    Ok(ReadDir { inner, path })
}

pub(crate) struct ReadDir {
    inner: tokio::fs::ReadDir,
    path: Utf8PathBuf,
}

impl Stream for ReadDir {
    type Item = Result<DirEntry, Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.inner.poll_next_entry(cx).map(|result| {
            result
                .and_then(|option| option.map(DirEntry::new).transpose())
                .map_err(|source| {
                    ErrorKind::ReadDir { source, path: Some(self.path.clone()) }
                        .into()
                })
                .transpose()
        })
    }
}

pub(crate) struct DirEntry {
    path: Utf8PathBuf,
}

impl DirEntry {
    fn new(inner: tokio::fs::DirEntry) -> Result<Self, std::io::Error> {
        let path =
            inner.path().try_into().map_err(FromPathBufError::into_io_error)?;
        Ok(Self { path })
    }

    pub(crate) fn into_path(self) -> Utf8PathBuf {
        self.path
    }

    pub(crate) fn path(&self) -> &Utf8Path {
        &self.path
    }

    pub(crate) fn file_name(&self) -> &str {
        self.path
            .file_name()
            .expect("path created through DirEntry must have a filename")
    }
}
