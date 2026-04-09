// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg(feature = "hubtools")]

use hubtools::Caboose;
use hubtools::CabooseError;

use crate::KnownArtifactTags;
use crate::RotBootloaderTags;
use crate::RotSign;
use crate::RotSlot;
use crate::RotTags;
use crate::SpTags;

impl RotTags {
    /// Attempts to read the values of `RotTags` from a Hubris caboose.
    ///
    /// `slot` is not part of the caboose and must be provided.
    ///
    /// # Errors
    ///
    /// Returns an error if the caboose is not valid, if `BORD` is not present,
    /// or if `BORD` or `SIGN` are not valid UTF-8 strings.
    pub fn from_caboose(
        caboose: &Caboose,
        slot: RotSlot,
    ) -> Result<Self, ReadCabooseError> {
        Ok(Self {
            rot_board: read_board(caboose)?,
            rot_sign: RotSign(read_sign(caboose)?),
            rot_slot: slot,
        })
    }
}

impl RotBootloaderTags {
    /// Attempts to read the values of `RotBootloaderTags` from a Hubris
    /// caboose.
    ///
    /// # Errors
    ///
    /// Returns an error if the caboose is not valid, if `BORD` is not present,
    /// or if `BORD` or `SIGN` are not valid UTF-8 strings.
    pub fn from_caboose(caboose: &Caboose) -> Result<Self, ReadCabooseError> {
        Ok(Self {
            rot_board: read_board(caboose)?,
            rot_sign: RotSign(read_sign(caboose)?),
        })
    }
}

impl SpTags {
    /// Attempts to read the values of `SpTags` from a Hubris caboose.
    ///
    /// # Errors
    ///
    /// Returns an error if the caboose is not valid, or if `BORD` is not
    /// present or is not not a valid UTF-8 string.
    pub fn from_caboose(caboose: &Caboose) -> Result<Self, ReadCabooseError> {
        Ok(Self { sp_board: read_board(caboose)? })
    }
}

impl KnownArtifactTags {
    /// Attempts to read the values of [`KnownArtifactTags::Rot`] from
    /// a Hubris caboose.
    ///
    /// `slot` is not part of the caboose and must be provided.
    ///
    /// # Errors
    ///
    /// Returns an error if the caboose is not valid, if `BORD` is not present,
    /// or if `BORD` or `SIGN` are not valid UTF-8 strings.
    pub fn from_rot_caboose(
        caboose: &Caboose,
        slot: RotSlot,
    ) -> Result<Self, ReadCabooseError> {
        RotTags::from_caboose(caboose, slot).map(KnownArtifactTags::Rot)
    }

    /// Attempts to read the values of [`KnownArtifactTags::RotBootloader`] from
    /// a Hubris caboose.
    ///
    /// # Errors
    ///
    /// Returns an error if the caboose is not valid, if `BORD` is not present,
    /// or if `BORD` or `SIGN` are not valid UTF-8 strings.
    pub fn from_rot_bootloader_caboose(
        caboose: &Caboose,
    ) -> Result<Self, ReadCabooseError> {
        RotBootloaderTags::from_caboose(caboose)
            .map(KnownArtifactTags::RotBootloader)
    }

    /// Attempts to read the values of [`KnownArtifactTags::Sp`] from a Hubris
    /// caboose.
    ///
    /// # Errors
    ///
    /// Returns an error if the caboose is not valid, or if `BORD` is not
    /// present or is not not a valid UTF-8 string.
    pub fn from_sp_caboose(
        caboose: &Caboose,
    ) -> Result<Self, ReadCabooseError> {
        SpTags::from_caboose(caboose).map(KnownArtifactTags::Sp)
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

/// An error that occurred while reading a Hubris archive.
#[derive(Debug, thiserror::Error)]
pub enum ReadCabooseError {
    /// The caboose was not valid, or the required tag was missing.
    #[error(transparent)]
    Caboose(#[from] hubtools::CabooseError),
    /// The tag value was not valid UTF-8.
    #[error("{tag} is not valid UTF-8")]
    Utf8 { tag: &'static str, source: std::str::Utf8Error },
}
