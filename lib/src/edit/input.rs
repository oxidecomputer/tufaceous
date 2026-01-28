// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
use tufaceous_artifact::RotTags;
use tufaceous_artifact::SpTags;
use tufaceous_artifact::ZoneTags;

use crate::COSMO_PHASE_1_PATH;
use crate::GIMLET_PHASE_1_PATH;
use crate::PHASE_2_PATH;
use crate::edit::source::BytesSource;
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
        tags: ZoneTags,
        version: ArtifactVersion,
    },
}

impl<Source> Input<Source> {
    pub(crate) fn outputs(self) -> Vec<Output<Source>> {
        match self {
            Input::MeasurementCorpus { source, corim_id, sha256, version } => {
                let target_name = format!(
                    "measurements/{corim_id}-{}.cbor",
                    hex::encode(sha256)
                );
                let tags = KnownArtifactTags::MeasurementCorpus;
                vec![Output::new(target_name, version, tags, source)]
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
                let mut vec = Vec::new();
                vec.push(Output::new(
                    base.join("image").join(COSMO_PHASE_1_PATH).into(),
                    version.clone(),
                    OsPhase1Tags { os_variant, os_board: OsBoard::Cosmo }
                        .into(),
                    cosmo_phase_1,
                ));
                vec.push(Output::new(
                    base.join("image").join(GIMLET_PHASE_1_PATH).into(),
                    version.clone(),
                    OsPhase1Tags { os_variant, os_board: OsBoard::Gimlet }
                        .into(),
                    gimlet_phase_1,
                ));
                vec.push(Output::new(
                    base.join("image").join(PHASE_2_PATH).into(),
                    version,
                    OsPhase2Tags { os_variant }.into(),
                    phase_2,
                ));
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
                    "rot/{board}-{sign}-{version}-slot-{slot}.zip",
                    board = tags.rot_board,
                    sign = tags.rot_sign,
                    slot = tags.rot_slot
                );
                vec![Output::new(target_name, version, tags.into(), source)]
            }
            Input::RotBootloader { source, tags, version } => {
                let target_name = format!(
                    "rot-bootloader/{board}-{sign}-{version}.zip",
                    board = tags.rot_board,
                    sign = tags.rot_sign
                );
                vec![Output::new(target_name, version, tags.into(), source)]
            }
            Input::Sp { source, tags, name, version } => {
                let target_name = format!("sp/{name}-{version}.zip");
                if tags.sp_board.as_str() == name {
                    vec![Output::new(target_name, version, tags.into(), source)]
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
            Input::Zone { source, tags, version } => {
                let target_name =
                    format!("zones/{name}.tar.gz", name = tags.zone_name);
                vec![Output::new(target_name, version, tags.into(), source)]
            }
        }
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
    tags: KnownArtifactTags,
    version: ArtifactVersion,
}

impl<Source> Output<Source> {
    pub(crate) fn new(
        target_name: String,
        version: ArtifactVersion,
        tags: KnownArtifactTags,
        source: Source,
    ) -> Self {
        Output {
            target_name,
            source,
            artifact_data: Some(ArtifactData { tags, version }),
        }
    }

    fn extra(target_name: String, source: Source) -> Self {
        Output { target_name, source, artifact_data: None }
    }

    pub(crate) fn to_artifact_schema(&self) -> Option<ArtifactSchema> {
        let data = self.artifact_data.as_ref()?;
        Some(ArtifactSchema {
            target_name: self.target_name.clone(),
            version: data.version.clone(),
            tags: data.tags.to_tags(),
        })
    }
}

impl Output<BytesSource> {
    pub(crate) fn into_artifact(self) -> Option<Artifact> {
        let data = self.artifact_data?;
        let mut hasher = Sha256::new();
        for bytes in self.source.iter_bytes() {
            hasher.update(bytes);
        }
        Some(Artifact {
            target_name: self.target_name,
            version: data.version,
            tags: data.tags.to_tags(),
            hash: ArtifactHash(hasher.finalize().into()),
            length: self.source.length(),
        })
    }
}
