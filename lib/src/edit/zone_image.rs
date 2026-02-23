// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::ControlFlow;

use bytes::BufMut;
use bytes::BytesMut;
use camino::Utf8PathBuf;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::ZoneTags;
use tufaceous_brand_metadata::ArchiveType;
use tufaceous_brand_metadata::LayerInfo;
use tufaceous_brand_metadata::Metadata;

use crate::edit::guess::GuessInput;
use crate::edit::guess::GuessResult;
use crate::edit::input::Input;
use crate::edit::source::BytesSource;
use crate::edit::source::FileSource;
use crate::edit::source::TargetSource;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::error::try_path;

impl Input<TargetSource<'static>> {
    pub(crate) async fn zone_image(path: Utf8PathBuf) -> Result<Self, Error> {
        let file =
            try_path!(tokio::fs::File::open(&path).await, OpenFile, path);
        let (file, layer_info) = crate::util::read_zone_layer_info(
            file.into_std().await,
            path.clone(),
        )
        .await?;
        let source = FileSource::from_file(file, path);
        Ok(Self::Zone {
            source: source.into(),
            tags: ZoneTags { zone_name: layer_info.pkg },
            version: layer_info.version,
        })
    }

    #[expect(clippy::unnecessary_wraps)]
    pub(crate) fn guess_zone_image(input: GuessInput) -> GuessResult {
        // `oxide.json` is the first file of a zone image and is relatively
        // small, so it should be contained entirely within the first 4K of the
        // compressed tarball.
        let mut archive = tar::Archive::new(GzDecoder::new(&*input.file_start));
        let Ok(layer_info) = Metadata::read_from_tar(&mut archive)
            .and_then(Metadata::into_layer_info)
        else {
            return Ok(ControlFlow::Continue(input));
        };
        Ok(ControlFlow::Break(Self::Zone {
            source: input.source.into(),
            tags: ZoneTags { zone_name: layer_info.pkg },
            version: layer_info.version,
        }))
    }
}

impl Input<BytesSource> {
    pub(crate) fn fake_zone_image(
        zone_name: String,
        version: ArtifactVersion,
        interior_version: Option<ArtifactVersion>,
    ) -> Result<Self, Error> {
        let mut archive = tar::Builder::new(GzEncoder::new(
            BytesMut::new().writer(),
            Compression::best(),
        ));
        let metadata = Metadata::new(ArchiveType::Layer(LayerInfo {
            pkg: zone_name.clone(),
            version: interior_version.unwrap_or_else(|| version.clone()),
        }));
        metadata
            .append_to_tar(&mut archive, 0)
            .map_err(ErrorKind::GenerateFakeZoneImage)?;
        let bytes = archive
            .into_inner()
            .and_then(GzEncoder::finish)
            .map_err(ErrorKind::GenerateFakeZoneImage)?
            .into_inner()
            .freeze();
        Ok(Input::Zone {
            source: BytesSource::new(bytes),
            tags: ZoneTags { zone_name },
            version,
        })
    }
}
