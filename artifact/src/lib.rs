// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! tufaceous-artifact defines the core types of tufaceous so that they can be
//! used without the full tufaceous library.

#![warn(missing_docs)]

mod artifact;
mod hubris;
mod installinator;
mod map;
mod metadata;
mod set;
mod sign;
mod tags;
mod version;

pub use artifact::*;
pub use hubris::ReadCabooseError;
pub use installinator::*;
pub use metadata::*;
pub use set::ArtifactSet;
pub use sign::*;
pub use tags::*;
pub use version::*;

/// Types related to [`ArtifactSet`].
pub mod artifact_set {
    pub use crate::set::GetError;
    pub use crate::set::IntoIter;
    pub use crate::set::Iter;
}
