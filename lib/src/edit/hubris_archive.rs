// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::ControlFlow;

use hubtools::Caboose;
use hubtools::CabooseBuilder;
use hubtools::HubrisArchiveBuilder;
use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::ReadCabooseError;
use tufaceous_artifact::RotBootloaderTags;
use tufaceous_artifact::RotKeyTableHash;
use tufaceous_artifact::RotSlot;
use tufaceous_artifact::RotTags;
use tufaceous_artifact::SpTags;

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
    pub(crate) async fn rot_archive(
        mut source: FileSource,
        caboose: Option<Caboose>,
        slot: RotSlot,
    ) -> Result<Self, Error> {
        let caboose = match caboose {
            Some(caboose) => caboose,
            None => source.read_hubris_caboose().await?,
        };
        let tags = try_path!(
            RotTags::from_caboose(&caboose, slot),
            ReadCaboose,
            source.path()
        );
        let version = try_path!(
            tag_helper(caboose.version(), "VERS"),
            ReadCaboose,
            source.path()
        )
        .parse()?;
        Ok(Self::Rot { source: source.into(), tags, version })
    }

    pub(crate) async fn rot_bootloader_archive(
        mut source: FileSource,
        caboose: Option<Caboose>,
    ) -> Result<Self, Error> {
        let caboose = match caboose {
            Some(caboose) => caboose,
            None => source.read_hubris_caboose().await?,
        };
        let tags = try_path!(
            RotBootloaderTags::from_caboose(&caboose),
            ReadCaboose,
            source.path()
        );
        let version = try_path!(
            tag_helper(caboose.version(), "VERS"),
            ReadCaboose,
            source.path()
        );
        Ok(Self::RotBootloader {
            source: source.into(),
            tags,
            version: version.parse()?,
        })
    }

    pub(crate) async fn sp_archive(
        mut source: FileSource,
        caboose: Option<Caboose>,
    ) -> Result<Self, Error> {
        let caboose = match caboose {
            Some(caboose) => caboose,
            None => source.read_hubris_caboose().await?,
        };
        let tags = try_path!(
            SpTags::from_caboose(&caboose),
            ReadCaboose,
            source.path()
        );
        let name = try_path!(
            tag_helper(caboose.name(), "NAME"),
            ReadCaboose,
            source.path()
        );
        let version = try_path!(
            tag_helper(caboose.version(), "VERS"),
            ReadCaboose,
            source.path()
        );
        Ok(Self::Sp {
            source: source.into(),
            tags,
            name,
            version: version.parse()?,
        })
    }

    pub(crate) async fn guess_hubris_archive(
        mut input: GuessInput,
    ) -> GuessResult {
        if !input.file_start.starts_with(b"PK\x03\x04") {
            return Ok(ControlFlow::Continue(input));
        }
        let Ok(archive) = input.source.read_hubris_archive().await else {
            return Ok(ControlFlow::Continue(input));
        };
        let Ok(caboose) = archive.read_caboose() else {
            return Ok(ControlFlow::Continue(input));
        };
        // HACK: We are reading the `image-name` file in the archive, which
        // appears to be "a" or "b" if it's an RoT image, "default" if it's
        // an SP image, and nonexistent if it's an RoT bootloader image. This
        // seems fragile. Ideally this can be in the caboose someday (see
        // sprot-release#74).
        match archive.image_name().as_deref() {
            Ok("a") => {
                Self::rot_archive(input.source, Some(caboose), RotSlot::A).await
            }
            Ok("b") => {
                Self::rot_archive(input.source, Some(caboose), RotSlot::B).await
            }
            Ok("default") => {
                Self::sp_archive(input.source, Some(caboose)).await
            }
            Err(hubtools::Error::MissingFile(_, _)) => {
                Self::rot_bootloader_archive(input.source, Some(caboose)).await
            }
            _ => return Ok(ControlFlow::Continue(input)),
        }
        .map(ControlFlow::Break)
    }
}

impl Input<BytesSource> {
    pub(crate) fn fake_rot_archive(
        tags: RotTags,
        version: ArtifactVersion,
        interior_version: Option<&ArtifactVersion>,
    ) -> Result<Self, Error> {
        let data = CabooseData {
            board: &tags.rot_board,
            rkth: &tags.rot_rkth,
            commit: "this-is-a-fake-rot",
            version: interior_version.unwrap_or(&version),
        };
        let source = data.generate_fake_archive()?;
        Ok(Input::Rot { source, tags, version })
    }

    pub(crate) fn fake_rot_bootloader_archive(
        tags: RotBootloaderTags,
        version: ArtifactVersion,
        interior_version: Option<&ArtifactVersion>,
    ) -> Result<Self, Error> {
        let data = CabooseData {
            board: &tags.rot_board,
            rkth: &tags.rot_rkth,
            commit: "this-is-a-fake-rot-bootloader",
            version: interior_version.unwrap_or(&version),
        };
        let source = data.generate_fake_archive()?;
        Ok(Input::RotBootloader { source, tags, version })
    }

    pub(crate) fn fake_sp_archive(
        tags: SpTags,
        version: ArtifactVersion,
        interior_version: Option<&ArtifactVersion>,
    ) -> Result<Self, Error> {
        let data = CabooseData {
            board: &tags.sp_board,
            rkth: &None,
            commit: "this-is-a-fake-sp",
            version: interior_version.unwrap_or(&version),
        };
        let source = data.generate_fake_archive()?;
        Ok(Input::Sp { source, name: tags.sp_board.clone(), tags, version })
    }
}

struct CabooseData<'a> {
    board: &'a str,
    rkth: &'a Option<RotKeyTableHash>,
    commit: &'static str,
    version: &'a ArtifactVersion,
}

impl CabooseData<'_> {
    fn generate_fake_archive(self) -> Result<BytesSource, Error> {
        let mut builder = CabooseBuilder::default()
            .board(self.board)
            .name(self.board)
            .git_commit(self.commit)
            .version(self.version.to_string());
        if let Some(rkth) = self.rkth {
            builder = builder.sign(rkth.as_str());
        }
        let caboose = builder.build();

        let mut builder = HubrisArchiveBuilder::with_fake_image();
        builder
            .write_caboose(caboose.as_slice())
            .map_err(ErrorKind::GenerateFakeHubrisArchive)?;
        let vec = builder
            .build_to_vec()
            .map_err(ErrorKind::GenerateFakeHubrisArchive)?;
        Ok(BytesSource::new(vec))
    }
}

fn tag_helper(
    value: Result<&[u8], hubtools::CabooseError>,
    tag: &'static str,
) -> Result<String, ReadCabooseError> {
    let s = std::str::from_utf8(value?)
        .map_err(|source| ReadCabooseError::Utf8 { tag, source })?;
    Ok(s.to_owned())
}
