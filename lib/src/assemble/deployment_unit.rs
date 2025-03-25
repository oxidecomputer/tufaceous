// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{collections::BTreeMap, fmt};

use daft::{Diffable, Leaf};
use thiserror::Error;
use tufaceous_artifact::{
    ArtifactHash, ArtifactKind, ArtifactVersion, KnownArtifactKind,
};

/// Information about deployment units for an artifact.
///
/// This information is used to ensure uniqueness of deployment units within a
/// particular scope.
pub type DeploymentUnitMap =
    BTreeMap<(ArtifactKind, ArtifactHash), DeploymentUnitData>;

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

/// Data associated with a deployment unit for a composite artifact.
#[derive(Clone, Debug)]
pub struct DeploymentUnitData {
    /// The name of the deployment unit.
    pub name: String,
    /// The version of the deployment unit.
    pub version: ArtifactVersion,
}

impl fmt::Display for DeploymentUnitData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "name: {}, version: {}", self.name, self.version)
    }
}

/// Builder for a composite artifact with deployment units.
#[derive(Clone, Debug)]
pub struct DeploymentUnitDataBuilder {
    scope: DeploymentUnitScope,
    deployment_units: DeploymentUnitMap,
}

impl DeploymentUnitDataBuilder {
    pub fn new(scope: DeploymentUnitScope) -> Self {
        Self { scope, deployment_units: BTreeMap::new() }
    }

    /// Starts adding a new deployment unit to `self`.
    pub fn start_add_deployment_unit(
        &mut self,
        kind: ArtifactKind,
        hash: ArtifactHash,
        data: DeploymentUnitData,
    ) -> Result<NewDeploymentUnits<'_>, DuplicateDeploymentUnitError> {
        if let Some(existing) = self.deployment_units.get(&(kind.clone(), hash))
        {
            return Err(DuplicateDeploymentUnitError::new_single(
                self.scope,
                kind,
                hash,
                existing.clone(),
                data,
            ));
        };

        Ok(NewDeploymentUnits::new_single(
            &mut self.deployment_units,
            kind,
            hash,
            data,
        ))
    }

    /// Starts a merge of another deployment unit map into `self`. The merge is
    /// not committed until `NewDeploymentUnits::commit` is called.
    ///
    /// Returns an error if any duplicates are found.
    pub fn start_merge_deployment_units(
        &mut self,
        units: DeploymentUnitMap,
    ) -> Result<NewDeploymentUnits<'_>, DuplicateDeploymentUnitError> {
        // Check that there are no duplicates. We don't expect to see any
        // duplicated artifacts at all within a single artifact or repository,
        // so we don't check whether the hashes are the same.
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
    pub fn add_deployment_unit(
        &mut self,
        kind: ArtifactKind,
        hash: ArtifactHash,
        data: DeploymentUnitData,
    ) -> Result<(), DuplicateDeploymentUnitError> {
        self.start_add_deployment_unit(kind, hash, data)?.insert();
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

/// Information about new deployment units for a [`DeploymentUnitDataBuilder`].
///
/// This serves as a way to make new deployment units ready to be inserted into
/// the builder.
#[must_use = "NewDeploymentUnits must be inserted into the builder"]
pub struct NewDeploymentUnits<'a> {
    base: &'a mut DeploymentUnitMap,
    units: DeploymentUnitMap,
}

impl<'a> NewDeploymentUnits<'a> {
    fn new_single(
        base: &'a mut DeploymentUnitMap,
        kind: ArtifactKind,
        hash: ArtifactHash,
        data: DeploymentUnitData,
    ) -> Self {
        let mut units = DeploymentUnitMap::new();
        units.insert((kind, hash), data);
        Self { base, units }
    }

    /// Inserts the deployment unit data into the builder.
    pub fn insert(self) {
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
    pub duplicates:
        BTreeMap<(ArtifactKind, ArtifactHash), Leaf<DeploymentUnitData>>,
}

impl DuplicateDeploymentUnitError {
    fn new_single(
        scope: DeploymentUnitScope,
        artifact_kind: ArtifactKind,
        artifact_hash: ArtifactHash,
        existing: DeploymentUnitData,
        new: DeploymentUnitData,
    ) -> Self {
        let mut duplicates = BTreeMap::new();
        duplicates.insert(
            (artifact_kind, artifact_hash),
            Leaf { before: existing, after: new },
        );
        Self { scope, duplicates }
    }
}

impl fmt::Display for DuplicateDeploymentUnitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // For a single deployment unit, we can simply display the artifact kind and hash.
        if self.duplicates.len() == 1 {
            let ((artifact_kind, artifact_hash), data) =
                self.duplicates.first_key_value().unwrap();
            write!(
                f,
                "a deployment unit with the same kind and hash already exists in this {}:\n\
                 kind: {}, hash: {} (existing {}; new {})",
                self.scope,
                artifact_kind,
                artifact_hash,
                data.before,
                data.after,
            )
        } else {
            writeln!(
                f,
                "{} deployment units with the same kind and hash already exist in this {}:",
                self.duplicates.len(),
                self.scope,
            )?;
            for ((artifact_kind, artifact_hash), data) in &self.duplicates {
                writeln!(
                    f,
                    "  - for kind: {}, hash: {}\
                     (existing: {}; new: {})",
                    artifact_kind, artifact_hash, data.before, data.after,
                )?;
            }

            Ok(())
        }
    }
}
