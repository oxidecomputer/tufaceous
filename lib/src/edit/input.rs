// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Indirection layer for logical sets of artifacts/targets.
//!
//! In the usual case, a file in a repository ("target" in TUF terms) is an
//! artifact that can be thought of as logically independent. The exception to
//! this general rule is OS images, which logically couple several phase 1 ROMs,
//! a phase 2 ZFS image, and extra non-artifact targets that are kept around for
//! archival purposes.
//!
//! An [`Input`] is a logical set of targets and their metadata, which can be
//! cheaply converted into a set of [`Output`]s. Each `Output` is the
//! [source data][crate::edit::source], the target name within the repository,
//! and if the target is an artifact, its version and tags.
//!
//! This indirection exists to make the behavior in the rest of the editor
//! module more consistent, as well as provide a single place where the
//! generated target names for artifacts are defined. This keeps target names
//! consistent across all real and fake repositories. Additionally, because
//! none of these methods are `async`, it is possible to generate a list of fake
//! artifacts in non-async code that will always be consistent with the set of
//! artifacts in a generated fake repository.

use std::collections::BTreeMap;

use camino::Utf8PathBuf;
use sha2::Digest;
use sha2::Sha256;
use tufaceous_artifact::Artifact;
use tufaceous_artifact::ArtifactHash;
use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::KnownArtifactTags;
use tufaceous_artifact::OsBoard;
use tufaceous_artifact::OsPhase1Tags;
use tufaceous_artifact::OsPhase2Tags;
use tufaceous_artifact::OsVariant;
use tufaceous_artifact::RotBootloaderTags;
use tufaceous_artifact::RotKeyTableHash;
use tufaceous_artifact::RotTags;
use tufaceous_artifact::SpTags;
use tufaceous_artifact::ZoneTags;

use crate::COSMO_PHASE_1_PATH;
use crate::GIMLET_PHASE_1_PATH;
use crate::PHASE_2_PATH;
use crate::edit::source::BytesSource;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::schema::ArtifactSchema;

#[derive(Debug)]
pub(crate) enum Input<Source> {
    MeasurementCorpus {
        source: Source,
        corim_id: String,
        sha256: ArtifactHash,
        version: ArtifactVersion,
    },
    OsImages {
        cosmo_phase_1: Source,
        gimlet_phase_1: Source,
        phase_2: Source,
        extra_targets: BTreeMap<String, Source>,
        os_variant: OsVariant,
        version: ArtifactVersion,
    },
    Rot {
        source: Source,
        tags: RotTags,
        version: ArtifactVersion,
    },
    RotBootloader {
        source: Source,
        tags: RotBootloaderTags,
        version: ArtifactVersion,
    },
    Sp {
        source: Source,
        tags: SpTags,
        name: String,
        version: ArtifactVersion,
    },
    Zone {
        source: Source,
        file_name: String,
        tags: ZoneTags,
        version: ArtifactVersion,
    },
}

impl<Source> Input<Source> {
    pub(crate) fn outputs(self) -> Result<Vec<Output<Source>>, Error> {
        Ok(match self {
            Input::MeasurementCorpus { source, corim_id, sha256, version } => {
                let target_name =
                    format!("measurements/{corim_id}-{sha256}.cbor",);
                let tags = KnownArtifactTags::MeasurementCorpus;
                vec![Output::new(target_name, version, &tags, source)?]
            }
            Input::OsImages {
                cosmo_phase_1,
                gimlet_phase_1,
                phase_2,
                extra_targets,
                os_variant,
                version,
            } => {
                let base = Utf8PathBuf::from(format!("os-{os_variant}"));
                let mut vec = Vec::with_capacity(3 + extra_targets.len());
                vec.push(Output::new(
                    base.join(COSMO_PHASE_1_PATH).into(),
                    version.clone(),
                    &OsPhase1Tags { os_board: OsBoard::COSMO, os_variant }
                        .into(),
                    cosmo_phase_1,
                )?);
                vec.push(Output::new(
                    base.join(GIMLET_PHASE_1_PATH).into(),
                    version.clone(),
                    &OsPhase1Tags { os_board: OsBoard::GIMLET, os_variant }
                        .into(),
                    gimlet_phase_1,
                )?);
                vec.push(Output::new(
                    base.join(PHASE_2_PATH).into(),
                    version,
                    &OsPhase2Tags { os_variant }.into(),
                    phase_2,
                )?);
                for (file_name, source) in extra_targets {
                    vec.push(Output::extra(
                        base.join(file_name).into(),
                        source,
                    ));
                }
                vec
            }
            Input::Rot { source, tags, version } => {
                let target_name = format!(
                    "rot/{board}-{rkth}-{version}-slot-{slot}.zip",
                    board = tags.rot_board,
                    rkth = tags
                        .rot_rkth
                        .as_ref()
                        .and_then(RotKeyTableHash::friendly_ca_name)
                        .unwrap_or("unsigned"),
                    slot = tags.rot_slot
                );
                vec![Output::new(target_name, version, &tags.into(), source)?]
            }
            Input::RotBootloader { source, tags, version } => {
                let target_name = format!(
                    "rot-bootloader/{board}-{rkth}-{version}.zip",
                    board = tags.rot_board,
                    rkth = tags
                        .rot_rkth
                        .as_ref()
                        .and_then(RotKeyTableHash::friendly_ca_name)
                        .unwrap_or("unsigned"),
                );
                vec![Output::new(target_name, version, &tags.into(), source)?]
            }
            Input::Sp { source, tags, name, version } => {
                let target_name = format!("sp/{name}-{version}.zip");
                if tags.sp_board.as_str() == name {
                    vec![Output::new(
                        target_name,
                        version,
                        &tags.into(),
                        source,
                    )?]
                } else {
                    // This is likely a lab image. As of writing these are
                    // stored in the TUF repo for manufacturing but are
                    // explicitly ignored by the control plane, as they can
                    // never be used in an actual rack. The current thinking is
                    // that they will eventually no longer need to be in the TUF
                    // repo. Add these as an extra target, not an artifact.
                    vec![Output::extra(target_name, source)]
                }
            }
            Input::Zone { source, file_name, tags, version } => {
                let target_name = format!("zones/{file_name}");
                vec![Output::new(target_name, version, &tags.into(), source)?]
            }
        })
    }
}

#[derive(Debug)]
pub(crate) struct Output<Source> {
    pub(crate) target_name: String,
    pub(crate) source: Source,
    artifact_data: Option<ArtifactData>,
}

#[derive(Debug)]
pub(crate) struct ArtifactData {
    tags: BTreeMap<String, String>,
    version: ArtifactVersion,
}

impl<Source> Output<Source> {
    pub(crate) fn new(
        target_name: String,
        version: ArtifactVersion,
        tags: &KnownArtifactTags,
        source: Source,
    ) -> Result<Self, Error> {
        let tags = tags.to_tags().map_err(ErrorKind::ConvertKnownTagsToMap)?;
        Ok(Output {
            target_name,
            source,
            artifact_data: Some(ArtifactData { tags, version }),
        })
    }

    fn extra(target_name: String, source: Source) -> Self {
        Output { target_name, source, artifact_data: None }
    }

    pub(crate) fn to_artifact_schema(&self) -> Option<ArtifactSchema> {
        let data = self.artifact_data.as_ref()?;
        Some(ArtifactSchema {
            target_name: self.target_name.clone(),
            version: data.version.clone(),
            tags: data.tags.clone(),
        })
    }
}

impl Output<BytesSource> {
    pub(crate) fn into_artifact(self) -> Option<(String, Artifact)> {
        let data = self.artifact_data?;
        let mut hasher = Sha256::new();
        for bytes in self.source.iter_bytes() {
            hasher.update(bytes);
        }
        Some((
            self.target_name,
            Artifact {
                version: data.version,
                tags: data.tags,
                hash: ArtifactHash(hasher.finalize().0),
                length: self.source.length(),
            },
        ))
    }
}
