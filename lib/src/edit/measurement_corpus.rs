// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::ControlFlow;

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
    ) -> Result<Self, Error> {
        let corim = if let Some(corim) = corim {
            corim
        } else {
            let v = source.read_to_end().await?;
            try_path!(Corim::from_bytes(v.as_slice()), ReadCorim, source.path())
        };
        let sha256 = source.sha256().await?;
        let version =
            try_path!(corim.get_version(), ReadCorim, source.path()).parse()?;
        Ok(Self::MeasurementCorpus {
            source: source.into(),
            corim_id: corim.id,
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
                    // This was plausibly a CoRIM manifest until we hit the end
                    // of the buffer, indicating a very high likelihood that if
                    // we read the entire thing it'd still be a CoRIM manifest.
                    None
                }
                Err(error) => {
                    eprintln!("{error:?}");
                    return Ok(ControlFlow::Continue(input));
                }
            };
        Self::measurement_corpus(input.source, corim)
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
        builder.version(version.to_string());
        for i in 0..hashes {
            builder.add_hash(format!("layer{i}"), 10, vec![0; 32]);
        }
        let corim = builder
            .build()
            .map_err(ErrorKind::GenerateFakeMeasurementCorpus)?;
        let bytes = corim
            .to_vec()
            .map_err(ErrorKind::SerializeFakeMeasurementCorpus)?;
        Ok(Input::MeasurementCorpus {
            corim_id: corim.id,
            sha256: ArtifactHash(Sha256::digest(&bytes).into()),
            source: BytesSource::new(bytes),
            version,
        })
    }
}

#[cfg(test)]
mod tests {
    use camino::Utf8Path;
    use futures_util::TryStreamExt;
    use futures_util::pin_mut;

    use crate::edit::guess::GuessInput;
    use crate::edit::input::Input;
    use crate::edit::source::FileSource;
    use crate::error::Error;

    #[tokio::test]
    async fn guess_partial_input() -> Result<(), Error> {
        const TRUNCATE_LEN: usize = 16;

        let path = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/corim-all-sp-v1.0.55.cbor");
        let metadata = tokio::fs::metadata(&path).await.unwrap();
        assert!(usize::try_from(metadata.len()).unwrap() > TRUNCATE_LEN);

        let source = FileSource::open(path).await?;
        // Read the first chunk from the stream, but truncate it to ensure
        // we hit the match arm where we correctly guess that this was an
        // incomplete read.
        let file_start = {
            let stream = source.stream();
            pin_mut!(stream);
            stream.try_next().await?.unwrap().split_to(TRUNCATE_LEN)
        };
        let input =
            Input::guess_measurement_corpus(GuessInput { file_start, source })
                .await?
                .break_value()
                .unwrap();
        assert!(matches!(input, Input::MeasurementCorpus { .. }));

        Ok(())
    }
}
