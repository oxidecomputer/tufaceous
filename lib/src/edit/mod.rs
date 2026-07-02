// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod editor;
mod fake;
mod guess;
mod hubris_archive;
mod input;
mod key;
mod measurement_corpus;
mod os_images;
mod root;
mod sign;
mod source;
mod zone_image;

pub use editor::*;
pub use fake::*;
pub use key::*;
pub use root::*;
pub use sign::*;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
#[expect(clippy::unreadable_literal)]
const OXIDE_BOOT_MAGIC: [u8; 4] = 0x1DEB0075_u32.to_le_bytes();
