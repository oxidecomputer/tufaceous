// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::ControlFlow;

use bytes::BufMut;
use bytes::BytesMut;
use rats_corim::Corim;
use rats_corim::CorimBuilder;
use sha2::Digest;
use sha2::Sha256;
use tufaceous_artifact::ArtifactHash;
use tufaceous_artifact::ArtifactVersion;

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
    pub(crate) async fn measurement_corpus(
        mut source: FileSource,
        corim: Option<Corim>,
        version: ArtifactVersion,
    ) -> Result<Self, Error> {
        let Corim { id, .. } = if let Some(corim) = corim {
            corim
        } else {
            let v = source.read_to_end().await?;
            try_path!(ciborium::from_reader(v.as_slice()), Corim, &source.path)
        };
        let sha256 = source.sha256().await?;
        Ok(Self::MeasurementCorpus {
            source: source.into(),
            corim_id: id,
            sha256,
            version,
        })
    }

    pub(crate) async fn guess_measurement_corpus(
        input: GuessInput,
    ) -> GuessResult {
        if !matches!(input.file_start[0], 0xa0..=0xbf /* CBOR map */) {
            return Ok(ControlFlow::Continue(input));
        }
        let corim =
            match ciborium::from_reader::<Corim, _>(&mut &*input.file_start) {
                Ok(corim) => Some(corim),
                Err(ciborium::de::Error::Io(err))
                    if err.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    // This was plausibly a CoRIM manifest until we hit the end of
                    // the buffer, indicating a very high likelihood that if we read
                    // the entire thing it'd still be a CoRIM manifest.
                    None
                }
                Err(_) => return Ok(ControlFlow::Continue(input)),
            };
        Self::measurement_corpus(input.source, corim, input.version)
            .await
            .map(ControlFlow::Break)
    }
}

impl Input<BytesSource> {
    pub(crate) fn fake_measurement_corpus(
        hashes: usize,
        version: ArtifactVersion,
    ) -> Result<Self, Error> {
        let mut builder = CorimBuilder::new();
        builder.vendor("fake-vendor".to_string());
        builder.id("fake-measurement-id".to_string());
        builder.tag_id("fake-tag-id".to_string());
        for i in 0..hashes {
            builder.add_hash(format!("layer{i}"), 10, vec![0; 32]);
        }
        let corim = builder
            .build()
            .map_err(ErrorKind::GenerateFakeMeasurementCorpus)?;

        let mut writer = BytesMut::new().writer();
        ciborium::into_writer(&corim, &mut writer)
            .map_err(ErrorKind::SerializeFakeMeasurementCorpus)?;
        let bytes = writer.into_inner().freeze();
        Ok(Input::MeasurementCorpus {
            corim_id: corim.id,
            sha256: ArtifactHash(Sha256::digest(&bytes).into()),
            source: BytesSource::new(bytes),
            version,
        })
    }
}
