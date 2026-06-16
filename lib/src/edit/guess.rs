// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::ControlFlow;

use bytes::Bytes;
use bytes::BytesMut;
use camino::Utf8PathBuf;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tufaceous_artifact::ArtifactVersion;

use crate::edit::input::Input;
use crate::edit::source::FileSource;
use crate::edit::source::TargetSource;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::error::try_path;

/// The input to guess methods: the first chunk of bytes from the file, and the
/// `FileSource` for converting into an [`Input`] if the guess method knows what
/// it is.
pub(crate) struct GuessInput {
    pub(crate) file_start: Bytes,
    pub(crate) source: FileSource,
}

/// A guess method can:
///
/// - say it knows what an input is, diverging the control flow:
///   `Ok(ControlFlow::Break(input))`
/// - say it doesn't know what an input is, returning the input and continuing
///   the control flow: `Ok(ControlFlow::Continue(guess_input))`
/// - return an error: `Err(error)`
pub(crate) type GuessResult =
    Result<ControlFlow<Input<TargetSource<'static>>, GuessInput>, Error>;

impl Input<TargetSource<'static>> {
    pub(crate) async fn guess(
        path: Utf8PathBuf,
        version: ArtifactVersion,
    ) -> Result<Self, Error> {
        if let Some(result) = Self::guess_os_images(&path, &version).await {
            return result;
        }

        let mut file = try_path!(File::open(&path).await, OpenFile, path);
        let mut buf = BytesMut::zeroed(4096);
        let n = try_path!(file.read(&mut buf).await, ReadFile, path);
        if n == 0 {
            // we're not going to try to guess an empty file
            return Err(ErrorKind::GuessArtifact { path }.into());
        }
        buf.truncate(n);

        let guess_input = GuessInput {
            file_start: buf.freeze(),
            source: FileSource::from_file(file.into_std().await, path.clone()),
        };
        let guess_input =
            match Self::guess_measurement_corpus(guess_input).await? {
                ControlFlow::Break(input) => return Ok(input),
                ControlFlow::Continue(guess_input) => guess_input,
            };
        let guess_input = match Self::guess_hubris_archive(guess_input).await? {
            ControlFlow::Break(input) => return Ok(input),
            ControlFlow::Continue(guess_input) => guess_input,
        };
        match Self::guess_zone_image(guess_input)? {
            ControlFlow::Break(input) => Ok(input),
            ControlFlow::Continue(_) => {
                Err(ErrorKind::GuessArtifact { path }.into())
            }
        }
    }
}
