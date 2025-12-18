// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg(feature = "hubtools")]

use hubtools::Caboose;
use hubtools::CabooseError;

use crate::KnownArtifactTags;
use crate::RotSlot;

impl KnownArtifactTags {
    pub fn from_rot_caboose(
        caboose: &Caboose,
        slot: RotSlot,
    ) -> Result<Self, ReadCabooseError> {
        Ok(KnownArtifactTags::Rot {
            board: read_board(caboose)?,
            sign: read_sign(caboose)?,
            slot,
        })
    }

    pub fn from_rot_bootloader_caboose(
        caboose: &Caboose,
    ) -> Result<Self, ReadCabooseError> {
        Ok(KnownArtifactTags::RotBootloader {
            board: read_board(caboose)?,
            sign: read_sign(caboose)?,
        })
    }

    pub fn from_sp_caboose(
        caboose: &Caboose,
    ) -> Result<Self, ReadCabooseError> {
        Ok(KnownArtifactTags::Sp { board: read_board(caboose)? })
    }
}

fn utf8<'a>(
    s: &'a [u8],
    tag: &'static str,
) -> Result<&'a str, ReadCabooseError> {
    std::str::from_utf8(s)
        .map_err(|source| ReadCabooseError::Utf8 { tag, source })
}

fn read_board(caboose: &Caboose) -> Result<String, ReadCabooseError> {
    Ok(utf8(caboose.board()?, "BORD")?.to_owned())
}

fn read_sign(caboose: &Caboose) -> Result<Option<String>, ReadCabooseError> {
    match caboose.sign() {
        Ok(sign) => Ok(Some(utf8(sign, "SIGN")?.to_owned())),
        Err(CabooseError::MissingTag { .. }) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub fn read_version(caboose: &Caboose) -> Result<&str, ReadCabooseError> {
    utf8(caboose.version()?, "VERS")
}

#[derive(Debug, thiserror::Error)]
pub enum ReadCabooseError {
    #[error(transparent)]
    Caboose(#[from] hubtools::CabooseError),
    #[error("{tag} is not valid UTF-8")]
    Utf8 { tag: &'static str, source: std::str::Utf8Error },
}
