// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// This library very commonly needs to convert from usize (Rust's standard
/// length type) to u64 (standard for file sizes in operating system APIs). This
/// is fallible so that Rust can be adapted to systems with pointer sizes larger
/// than 64 bits. In 2026 these systems do not appear to exist nor appear to be
/// on the horizon.
///
/// This is a shorthand to assert that a value is a usize, then convert and
/// panic on failure; the failure is impossible and elided on 64-bit or lower
/// systems.
macro_rules! usize64 {
    ($usize:expr) => {{
        let x: usize = $usize;
        u64::try_from(x).expect("usize fits in u64")
    }};
}

pub mod edit;
pub mod error;
mod loader;
mod mpsc_stream;
mod repo;
mod schema;
mod util;
mod zip_transport;

pub use loader::*;
pub use repo::*;
pub use zip_transport::*;

pub(crate) const COSMO_PHASE_1_PATH: &str = "cosmo.rom";
pub(crate) const GIMLET_PHASE_1_PATH: &str = "gimlet.rom";
pub(crate) const PHASE_2_PATH: &str = "zfs.img";
