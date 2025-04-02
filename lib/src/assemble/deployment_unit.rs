// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{collections::BTreeMap, fmt};

use daft::{Diffable, Leaf};
use thiserror::Error;
use tufaceous_artifact::{
    ArtifactHash, ArtifactHashId, ArtifactKind, ArtifactVersion,
    KnownArtifactKind,
};

/// Information about deployment units keyed by hash ID.
///
/// This information is used to ensure uniqueness of deployment units within a
/// particular scope.
pub type DeploymentUnitMap = BTreeMap<ArtifactHashId, DeploymentUnitData>;

/// Information about deployment units for an artifact.
#[derive(Clone, Debug)]
pub enum ArtifactDeploymentUnits {
    /// This artifact is single-unit (not composite). There is exactly one
    /// deployment unit, which is the artifact itself.
    SingleUnit,

    /// This is a composite artifact, with these deployment units.
    Composite { deployment_units: DeploymentUnitMap },

    /// Data was not available for this artifact.
    Unknown,
}

/// Ths scope in which deployment unit data is being gathered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentUnitScope {
    /// Deployment units are being gathered for a single composite artifact.
    Artifact {
        /// The kind of the composite artifact.
        composite_kind: KnownArtifactKind,
    },

    /// Deployment units are being gathered for a repository.
    Repository,
}

impl fmt::Display for DeploymentUnitScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeploymentUnitScope::Artifact { composite_kind } => {
                write!(f, "{composite_kind} artifact")
            }
            DeploymentUnitScope::Repository => "repository".fmt(f),
        }
    }
}

/// Data associated with a deployment unit.
#[derive(Clone, Debug)]
pub struct DeploymentUnitData {
    /// The name of the deployment unit.
    pub name: String,

    /// The version of the deployment unit.
    pub version: ArtifactVersion,

    /// The kind of the deployment unit.
    pub kind: ArtifactKind,

    /// The hash of the deployment unit.
    pub hash: ArtifactHash,
}

impl DeploymentUnitData {
    /// Returns the [`ArtifactHashId`] of the deployment unit.
    #[inline]
    pub fn hash_id(&self) -> ArtifactHashId {
        ArtifactHashId { kind: self.kind.clone(), hash: self.hash }
    }
}

impl fmt::Display for DeploymentUnitData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "name: {}, version: {}", self.name, self.version)
    }
}

/// Builder for a [`DeploymentUnitMap`].
///
/// This builder ensures uniqueness of deployment units within a particular
/// [`DeploymentUnitScope`].
#[derive(Clone, Debug)]
pub struct DeploymentUnitMapBuilder {
    scope: DeploymentUnitScope,
    // TODO: This should also check for duplicate name/version/kind. Will
    // probably want to use a data structure more tailored for this.
    deployment_units: DeploymentUnitMap,
}

impl DeploymentUnitMapBuilder {
    pub fn new(scope: DeploymentUnitScope) -> Self {
        Self { scope, deployment_units: BTreeMap::new() }
    }

    /// Starts adding a new deployment unit to `self`.
    pub fn start_insert(
        &mut self,
        data: DeploymentUnitData,
    ) -> Result<NewDeploymentUnits<'_>, DuplicateDeploymentUnitError> {
        let hash_id = data.hash_id();
        if let Some(existing) = self.deployment_units.get(&hash_id) {
            return Err(DuplicateDeploymentUnitError::new_single(
                self.scope,
                existing.clone(),
                data,
            ));
        };

        Ok(NewDeploymentUnits::new_single(&mut self.deployment_units, data))
    }

    /// Starts a bulk insert of another deployment unit map into `self`. The
    /// merge is not committed until `NewDeploymentUnits::commit` is called.
    ///
    /// Returns an error if any duplicates are found.
    pub fn start_bulk_insert(
        &mut self,
        units: DeploymentUnitMap,
    ) -> Result<NewDeploymentUnits<'_>, DuplicateDeploymentUnitError> {
        // Check that there are no duplicates. We don't expect to see any
        // duplicated artifacts at all within a single artifact or repository,
        // so we don't check whether the hashes are the same.
        //
        // In order for this check to be done now rather than at commit time, we
        // rely on two things:
        //
        // 1. `start_bulk_insert` accepts a `&mut self` parameter.
        // 2. There is no interior mutability in `DeploymentUnitMapBuilder`.
        //
        // Together, these two checks ensure that nothing else can modify the
        // map between now and either commit or discard.
        let diff = self.deployment_units.diff(&units);

        if !diff.common.is_empty() {
            return Err(DuplicateDeploymentUnitError {
                scope: self.scope,
                duplicates: diff
                    .common
                    .into_iter()
                    .map(|(k, v)| (k.clone(), v.cloned()))
                    .collect(),
            });
        }

        Ok(NewDeploymentUnits { base: &mut self.deployment_units, units })
    }

    /// Convenience method for `self.start_add_deployment_unit(..).insert()` for a
    /// single deployment unit.
    pub fn insert(
        &mut self,
        data: DeploymentUnitData,
    ) -> Result<(), DuplicateDeploymentUnitError> {
        self.start_insert(data)?.commit();
        Ok(())
    }

    pub fn finish_map(self) -> DeploymentUnitMap {
        self.deployment_units
    }

    pub fn finish_units(self) -> ArtifactDeploymentUnits {
        ArtifactDeploymentUnits::Composite {
            deployment_units: self.deployment_units,
        }
    }
}

/// Information about new deployment units for a [`DeploymentUnitMapBuilder`].
///
/// This serves as a way to make new deployment units ready to be bulk-inserted
/// into the builder.
#[must_use = "NewDeploymentUnits must be committed into the builder"]
pub struct NewDeploymentUnits<'a> {
    base: &'a mut DeploymentUnitMap,
    units: DeploymentUnitMap,
}

impl<'a> NewDeploymentUnits<'a> {
    fn new_single(
        base: &'a mut DeploymentUnitMap,
        data: DeploymentUnitData,
    ) -> Self {
        let mut units = DeploymentUnitMap::new();
        units.insert(data.hash_id(), data);
        Self { base, units }
    }

    /// Inserts the deployment unit data into the builder.
    pub fn commit(self) {
        self.base.extend(self.units);
    }
}

#[derive(Clone, Debug, Error)]
pub struct DuplicateDeploymentUnitError {
    /// The scope within which duplicates were found.
    pub scope: DeploymentUnitScope,

    /// Duplicates found while inserting deployment unit data.
    ///
    /// For `Leaf<DeploymentUnitData>`, `before` is the existing data and
    /// `after` is the new data.
    pub duplicates: BTreeMap<ArtifactHashId, Leaf<DeploymentUnitData>>,
}

impl DuplicateDeploymentUnitError {
    // Note: existing and new should have the same hash_id.
    fn new_single(
        scope: DeploymentUnitScope,
        existing: DeploymentUnitData,
        new: DeploymentUnitData,
    ) -> Self {
        let mut duplicates = BTreeMap::new();
        let hash_id = existing.hash_id();
        duplicates.insert(hash_id, Leaf { before: existing, after: new });
        Self { scope, duplicates }
    }
}

impl fmt::Display for DuplicateDeploymentUnitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // For a single deployment unit, we can simply display the artifact kind and hash.
        if self.duplicates.len() == 1 {
            let (hash_id, data) = self.duplicates.first_key_value().unwrap();
            // XXX: should `ArtifactHashId` have a `Display` impl, or maybe a
            // `.display()` or `.display_human()` method?
            write!(
                f,
                "a deployment unit with the same kind and hash already exists in this {}:\n\
                 {hash_id} (existing {}; new {})",
                self.scope, data.before, data.after,
            )
        } else {
            writeln!(
                f,
                "{} deployment units with the same kind and hash already exist in this {}:",
                self.duplicates.len(),
                self.scope,
            )?;
            for (hash_id, data) in &self.duplicates {
                writeln!(
                    f,
                    "  - for {hash_id} (existing: {}; new: {})",
                    data.before, data.after,
                )?;
            }

            Ok(())
        }
    }
}
