// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufReader;
use std::str::FromStr;
use std::{fmt, fs};

use anyhow::{Context, Result, bail, ensure};
use camino::{Utf8Path, Utf8PathBuf};
use itertools::Itertools;
use parse_size::parse_size;
use semver::Version;
use serde::{Deserialize, Serialize};
use tufaceous_artifact::{ArtifactKind, ArtifactVersion, KnownArtifactKind};

use crate::assemble::{DeploymentUnitData, DeploymentUnitScope};
use crate::{
    ArtifactSource, CompositeControlPlaneArchiveBuilder, CompositeEntry,
    CompositeHostArchiveBuilder, CompositeRotArchiveBuilder,
    HOST_PHASE_1_FILE_NAME, HOST_PHASE_2_FILE_NAME, HostPhaseImages,
    MtimeSource, ROT_ARCHIVE_A_FILE_NAME, ROT_ARCHIVE_B_FILE_NAME,
    make_filler_text,
};

use super::{ArtifactDeploymentUnits, DeploymentUnitMapBuilder};

static FAKE_MANIFEST_TOML: &str =
    include_str!("../../../bin/manifests/fake.toml");

/// A list of components in a TUF repo representing a single update.
#[derive(Clone, Debug)]
pub struct ArtifactManifest {
    pub system_version: Version,
    pub artifacts: BTreeMap<KnownArtifactKind, Vec<ArtifactData>>,
}

impl ArtifactManifest {
    /// Reads a manifest in from a TOML file.
    pub fn from_path(path: &Utf8Path) -> Result<Self> {
        let input = fs_err::read_to_string(path)?;
        let base_dir = path
            .parent()
            .with_context(|| format!("path `{path}` did not have a parent"))?;
        Self::from_str(base_dir, &input)
    }

    /// Deserializes a manifest from an input string.
    pub fn from_str(base_dir: &Utf8Path, input: &str) -> Result<Self> {
        let manifest = DeserializedManifest::from_str(input)?;
        Self::from_deserialized(base_dir, manifest)
    }

    /// Creates a manifest from a [`DeserializedManifest`].
    pub fn from_deserialized(
        base_dir: &Utf8Path,
        manifest: DeserializedManifest,
    ) -> Result<Self> {
        // Replace all paths in the deserialized manifest with absolute ones,
        // and do some processing to support flexible manifests:
        //
        // 1. assemble any composite artifacts from their pieces
        // 2. replace any "fake" artifacts with in-memory buffers
        //
        // Currently both of those transformations produce
        // `ArtifactSource::Memory(_)` variants (i.e., composite and fake
        // artifacts all sit in-memory until we're done with the manifest),
        // which puts some limits on how large the inputs to the manifest can
        // practically be. If this becomes onerous, we could instead write the
        // transformed artifacts to temporary files.
        //
        // We do some additional error checking here to make sure the
        // `CompositeZZZ` variants are only used with their corresponding
        // `KnownArtifactKind`s. It would be nicer to enforce this more
        // statically and let serde do these checks, but that seems relatively
        // tricky in comparison to these checks.

        Ok(ArtifactManifest {
            system_version: manifest.system_version,
            artifacts: manifest
                .artifacts
                .into_iter()
                .map(|(kind, entries)| {
                    Self::parse_deserialized_entries(base_dir, kind, entries)
                })
                .collect::<Result<_, _>>()?,
        })
    }

    fn parse_deserialized_entries(
        base_dir: &Utf8Path,
        kind: KnownArtifactKind,
        entries: Vec<DeserializedArtifactData>,
    ) -> Result<(KnownArtifactKind, Vec<ArtifactData>)> {
        let entries = entries
            .into_iter()
            .map(|artifact_data| {
                let (source, deployment_units) = match artifact_data.source {
                    DeserializedArtifactSource::File { path } => {
                        let path = base_dir.join(&path);

                        // Host images are actually composite artifacts, and we
                        // need to treat them that way for installinator.
                        let deployment_units =
                            if kind == KnownArtifactKind::Host {
                                let file =
                                fs::File::open(&path).with_context(|| {
                                    format!(
                                        "error opening host image at `{path}`"
                                    )
                                })?;
                                let reader = BufReader::new(file);
                                let images = HostPhaseImages::extract(reader)?;

                                let mut data_builder =
                                    DeploymentUnitMapBuilder::new(
                                        DeploymentUnitScope::Artifact {
                                            composite_kind: kind,
                                        },
                                    );
                                data_builder
                                    .insert(DeploymentUnitData {
                                        name: HOST_PHASE_1_FILE_NAME.to_owned(),
                                        version: artifact_data.version.clone(),
                                        kind: ArtifactKind::HOST_PHASE_1,
                                        hash: images.phase_1_hash(),
                                    })
                                    .expect("unique kind");
                                data_builder
                                    .insert(DeploymentUnitData {
                                        name: HOST_PHASE_2_FILE_NAME.to_owned(),
                                        version: artifact_data.version.clone(),
                                        kind: ArtifactKind::HOST_PHASE_2,
                                        hash: images.phase_2_hash(),
                                    })
                                    .expect("unique kind");

                                data_builder.finish_units()
                            } else {
                                // It would be nice to extract other kinds of
                                // composite artifacts here, but (a) we don't
                                // have a need for that in this case and (b) the
                                // code for that currently lives in omicron's
                                // update-common.
                                ArtifactDeploymentUnits::SingleUnit
                            };

                        (ArtifactSource::File(path), deployment_units)
                    }
                    DeserializedArtifactSource::Fake { size, data_version } => {
                        // This test-only environment variable is used to
                        // simulate two artifacts with different
                        // name/version/kind but the same hash.
                        let data_version = data_version
                            .as_ref()
                            .unwrap_or(&artifact_data.version);
                        let fake_data =
                            FakeDataAttributes::new(kind, data_version)
                                .make_data(size as usize);
                        (
                            ArtifactSource::Memory(fake_data.into()),
                            ArtifactDeploymentUnits::SingleUnit,
                        )
                    }
                    DeserializedArtifactSource::CompositeHost {
                        phase_1,
                        phase_2,
                    } => {
                        ensure!(
                            matches!(
                                kind,
                                KnownArtifactKind::Host
                                    | KnownArtifactKind::Trampoline
                            ),
                            "`composite_host` source cannot be used with \
                             artifact kind {kind:?}"
                        );

                        let mtime_source =
                            if phase_1.is_fake() && phase_2.is_fake() {
                                // Ensure stability of fake artifacts.
                                MtimeSource::Zero
                            } else {
                                MtimeSource::Now
                            };

                        let mut builder = CompositeHostArchiveBuilder::new(
                            Vec::new(),
                            mtime_source,
                        )?;
                        let phase_1_hash = phase_1.with_entry(
                            FakeDataAttributes::new(
                                kind,
                                &artifact_data.version,
                            ),
                            |entry| builder.append_phase_1(entry),
                        )?;
                        let phase_2_hash = phase_2.with_entry(
                            FakeDataAttributes::new(
                                kind,
                                &artifact_data.version,
                            ),
                            |entry| builder.append_phase_2(entry),
                        )?;
                        let source =
                            ArtifactSource::Memory(builder.finish()?.into());

                        let mut data_builder = DeploymentUnitMapBuilder::new(
                            DeploymentUnitScope::Artifact {
                                composite_kind: kind,
                            },
                        );
                        data_builder
                            .insert(DeploymentUnitData {
                                name: HOST_PHASE_1_FILE_NAME.to_owned(),
                                version: artifact_data.version.clone(),
                                kind: ArtifactKind::HOST_PHASE_1,
                                hash: phase_1_hash,
                            })
                            .expect("unique kind");
                        data_builder
                            .insert(DeploymentUnitData {
                                name: HOST_PHASE_2_FILE_NAME.to_owned(),
                                version: artifact_data.version.clone(),
                                kind: ArtifactKind::HOST_PHASE_2,
                                hash: phase_2_hash,
                            })
                            .expect("unique kind");

                        (source, data_builder.finish_units())
                    }
                    DeserializedArtifactSource::CompositeRot {
                        archive_a,
                        archive_b,
                    } => {
                        let (a_kind, b_kind) =
                            kind.rot_a_and_b_kinds().context(
                                "`composite_rot` source cannot be used with \
                                 non-RoT artifact kind",
                            )?;

                        let mtime_source =
                            if archive_a.is_fake() && archive_b.is_fake() {
                                // Ensure stability of fake artifacts.
                                MtimeSource::Zero
                            } else {
                                MtimeSource::Now
                            };

                        let mut builder = CompositeRotArchiveBuilder::new(
                            Vec::new(),
                            mtime_source,
                        )?;
                        let archive_a_hash = archive_a.with_entry(
                            FakeDataAttributes::new(
                                kind,
                                &artifact_data.version,
                            ),
                            |entry| builder.append_archive_a(entry),
                        )?;
                        let archive_b_hash = archive_b.with_entry(
                            FakeDataAttributes::new(
                                kind,
                                &artifact_data.version,
                            ),
                            |entry| builder.append_archive_b(entry),
                        )?;

                        let mut data_builder = DeploymentUnitMapBuilder::new(
                            DeploymentUnitScope::Artifact {
                                composite_kind: kind,
                            },
                        );
                        data_builder
                            .insert(DeploymentUnitData {
                                name: ROT_ARCHIVE_A_FILE_NAME.to_owned(),
                                version: artifact_data.version.clone(),
                                kind: a_kind,
                                hash: archive_a_hash,
                            })
                            .expect("unique kind in empty map");
                        data_builder
                            .insert(DeploymentUnitData {
                                name: ROT_ARCHIVE_B_FILE_NAME.to_owned(),
                                version: artifact_data.version.clone(),
                                kind: b_kind,
                                hash: archive_b_hash,
                            })
                            .expect("unique kind in empty map");

                        (
                            ArtifactSource::Memory(builder.finish()?.into()),
                            data_builder.finish_units(),
                        )
                    }
                    DeserializedArtifactSource::CompositeControlPlane {
                        zones,
                    } => {
                        ensure!(
                            kind == KnownArtifactKind::ControlPlane,
                            "`composite_control_plane` source cannot be \
                             used with artifact kind {kind:?}"
                        );

                        // Ensure stability of fake artifacts.
                        let mtime_source = if zones.iter().all(|z| z.is_fake())
                        {
                            MtimeSource::Zero
                        } else {
                            MtimeSource::Now
                        };

                        let data = Vec::new();
                        let mut builder =
                            CompositeControlPlaneArchiveBuilder::new(
                                data,
                                mtime_source,
                            )?;

                        let zone_kind =
                            ArtifactKind::from(KnownArtifactKind::Zone);
                        let mut data_builder = DeploymentUnitMapBuilder::new(
                            DeploymentUnitScope::Artifact {
                                composite_kind: kind,
                            },
                        );

                        for zone in zones {
                            let (hash, name) = zone.with_name_and_entry(
                                &artifact_data.version,
                                |name, entry| builder.append_zone(name, entry),
                            )?;
                            data_builder.insert(DeploymentUnitData {
                                name: name.to_owned(),
                                version: artifact_data.version.clone(),
                                kind: zone_kind.clone(),
                                hash,
                            })?;
                        }
                        (
                            ArtifactSource::Memory(builder.finish()?.into()),
                            data_builder.finish_units(),
                        )
                    }
                };
                let data = ArtifactData {
                    name: artifact_data.name,
                    version: artifact_data.version,
                    source,
                    deployment_units,
                };
                Ok(data)
            })
            .collect::<Result<_, _>>()?;
        Ok((kind, entries))
    }

    /// Returns a fake manifest. Useful for testing.
    pub fn new_fake() -> Self {
        // The base directory doesn't matter for fake manifests.
        Self::from_str(".".into(), FAKE_MANIFEST_TOML)
            .expect("the fake manifest is a valid manifest")
    }

    /// Checks that all versions are valid semver.
    pub fn verify_all_semver(&self) -> Result<()> {
        let mut non_semver = Vec::new();
        for artifacts in self.artifacts.values() {
            for artifact in artifacts {
                if artifact.version.as_str().parse::<Version>().is_err() {
                    non_semver.push(artifact);
                }
            }
        }

        if !non_semver.is_empty() {
            bail!(
                "non-semver versions found: {}",
                non_semver.iter().map(|d| d.display()).join(", "),
            );
        }
        Ok(())
    }

    /// Checks that all expected artifacts are present, returning an error with
    /// details if any artifacts are missing.
    pub fn verify_all_present(&self) -> Result<()> {
        let all_artifacts: BTreeSet<_> = KnownArtifactKind::iter()
            .filter(|k| !matches!(k, KnownArtifactKind::Zone))
            .collect();
        let present_artifacts: BTreeSet<_> =
            self.artifacts.keys().copied().collect();

        let missing = &all_artifacts - &present_artifacts;
        if !missing.is_empty() {
            bail!(
                "manifest has missing artifacts: {}",
                itertools::join(missing, ", ")
            );
        }

        Ok(())
    }
}

#[derive(Debug)]
struct FakeDataAttributes<'a> {
    kind: KnownArtifactKind,
    version: &'a ArtifactVersion,
}

impl<'a> FakeDataAttributes<'a> {
    fn new(kind: KnownArtifactKind, version: &'a ArtifactVersion) -> Self {
        Self { kind, version }
    }

    fn make_data(&self, size: usize) -> Vec<u8> {
        use hubtools::{CabooseBuilder, HubrisArchiveBuilder};

        let board = match self.kind {
            KnownArtifactKind::GimletRotBootloader
            | KnownArtifactKind::PscRotBootloader
            | KnownArtifactKind::SwitchRotBootloader => "SimRotStage0",
            // non-Hubris artifacts: just make fake data
            KnownArtifactKind::Host
            | KnownArtifactKind::Trampoline
            | KnownArtifactKind::ControlPlane
            | KnownArtifactKind::Zone => {
                return make_filler_text(
                    &self.kind.to_string(),
                    self.version,
                    size,
                );
            }
            KnownArtifactKind::InstallinatorDocument => {
                panic!(
                    "fake manifest should not have an installinator document"
                );
            }

            // hubris artifacts: build a fake archive (SimGimletSp and
            // SimGimletRot are used by sp-sim)
            KnownArtifactKind::GimletSp => "SimGimletSp",
            KnownArtifactKind::GimletRot => "SimRot",
            KnownArtifactKind::PscSp => "fake-psc-sp",
            KnownArtifactKind::PscRot => "fake-psc-rot",
            KnownArtifactKind::SwitchSp => "SimSidecarSp",
            KnownArtifactKind::SwitchRot => "SimRot",
        };

        // For our purposes sign = board represents what we want for the RoT
        // and we don't care about the sign value for the SP
        // We now have an assumption that board == name for our production
        // images
        let caboose = CabooseBuilder::default()
            .git_commit("this-is-fake-data")
            .board(board)
            .version(self.version.to_string())
            .name(board)
            .sign(board)
            .build();

        let mut builder = HubrisArchiveBuilder::with_fake_image();
        builder.write_caboose(caboose.as_slice()).unwrap();
        builder.build_to_vec().unwrap()
    }
}

/// Information about an individual artifact.
#[derive(Clone, Debug)]
pub struct ArtifactData {
    pub name: String,
    pub version: ArtifactVersion,
    pub source: ArtifactSource,
    pub deployment_units: ArtifactDeploymentUnits,
}

impl ArtifactData {
    /// Returns a displayer for the name and version of the artifact.
    pub fn display(&self) -> ArtifactDataDisplay<'_> {
        ArtifactDataDisplay { data: self }
    }
}

pub struct ArtifactDataDisplay<'a> {
    data: &'a ArtifactData,
}

impl fmt::Display for ArtifactDataDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.data.name, self.data.version)
    }
}

/// Deserializable version of [`ArtifactManifest`].
///
/// Since manifests require a base directory to be deserialized properly,
/// we don't expose the `Deserialize` impl on `ArtifactManifest, forcing
/// consumers to go through [`ArtifactManifest::from_path`] or
/// [`ArtifactManifest::from_str`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DeserializedManifest {
    pub system_version: Version,
    #[serde(rename = "artifact")]
    pub artifacts: BTreeMap<KnownArtifactKind, Vec<DeserializedArtifactData>>,
}

impl DeserializedManifest {
    pub fn from_path(path: &Utf8Path) -> Result<Self> {
        let input = fs_err::read_to_string(path)?;
        Self::from_str(&input).with_context(|| {
            format!("error deserializing manifest from {path}")
        })
    }

    pub fn to_toml(&self) -> Result<String> {
        toml::to_string(self).context("error serializing manifest to TOML")
    }

    /// For fake manifests, applies a set of changes to them.
    ///
    /// Intended for testing.
    pub fn apply_tweaks(&mut self, tweaks: &[ManifestTweak]) -> Result<()> {
        for tweak in tweaks {
            match tweak {
                ManifestTweak::SystemVersion(version) => {
                    self.system_version = version.clone();
                }
                ManifestTweak::ArtifactVersion { kind, version } => {
                    let entries =
                        self.artifacts.get_mut(kind).with_context(|| {
                            format!(
                                "manifest does not have artifact kind \
                                 {kind}",
                            )
                        })?;
                    for entry in entries {
                        entry.version = version.clone();
                    }
                }
                ManifestTweak::ArtifactSize { kind, size_delta } => {
                    let entries =
                        self.artifacts.get_mut(kind).with_context(|| {
                            format!(
                                "manifest does not have artifact kind \
                                 {kind}",
                            )
                        })?;

                    for entry in entries {
                        entry.source.apply_size_delta(*size_delta)?;
                    }
                }
                ManifestTweak::ArtifactDataVersion { kind, data_version } => {
                    let entries =
                        self.artifacts.get_mut(kind).with_context(|| {
                            format!(
                                "manifest does not have artifact kind \
                                 {kind}",
                            )
                        })?;

                    for entry in entries {
                        entry
                            .source
                            .apply_data_version(data_version.as_ref())?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Returns the fake manifest.
    pub fn fake() -> Self {
        Self::from_str(FAKE_MANIFEST_TOML).unwrap()
    }

    /// Returns a version of the fake manifest with a set of changes applied.
    ///
    /// This is primarily intended for testing.
    pub fn tweaked_fake(tweaks: &[ManifestTweak]) -> Self {
        let mut manifest = Self::fake();
        manifest
            .apply_tweaks(tweaks)
            .expect("builtin fake manifest should accept all tweaks");

        manifest
    }
}

impl FromStr for DeserializedManifest {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let de = toml::Deserializer::new(input);
        serde_path_to_error::deserialize(de)
            .context("error deserializing manifest")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DeserializedArtifactData {
    pub name: String,
    pub version: ArtifactVersion,
    pub source: DeserializedArtifactSource,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DeserializedArtifactSource {
    File {
        path: Utf8PathBuf,
    },
    Fake {
        #[serde(deserialize_with = "deserialize_byte_size")]
        size: u64,
        /// The internal version to use while constructing the fake artifact
        /// data.
        ///
        /// If not set, the artifact's version is used.
        #[serde(default)]
        data_version: Option<ArtifactVersion>,
    },
    CompositeHost {
        phase_1: DeserializedFileArtifactSource,
        phase_2: DeserializedFileArtifactSource,
    },
    CompositeRot {
        archive_a: DeserializedFileArtifactSource,
        archive_b: DeserializedFileArtifactSource,
    },
    CompositeControlPlane {
        zones: Vec<DeserializedControlPlaneZoneSource>,
    },
}

impl DeserializedArtifactSource {
    fn apply_size_delta(&mut self, size_delta: i64) -> Result<()> {
        match self {
            DeserializedArtifactSource::File { .. } => {
                bail!("cannot apply size delta to `file` source")
            }
            DeserializedArtifactSource::Fake { size, data_version: _ } => {
                *size = (*size).saturating_add_signed(size_delta);
                Ok(())
            }
            DeserializedArtifactSource::CompositeHost { phase_1, phase_2 } => {
                phase_1.apply_size_delta(size_delta)?;
                phase_2.apply_size_delta(size_delta)?;
                Ok(())
            }
            DeserializedArtifactSource::CompositeRot {
                archive_a,
                archive_b,
            } => {
                archive_a.apply_size_delta(size_delta)?;
                archive_b.apply_size_delta(size_delta)?;
                Ok(())
            }
            DeserializedArtifactSource::CompositeControlPlane { zones } => {
                for zone in zones {
                    zone.apply_size_delta(size_delta)?;
                }
                Ok(())
            }
        }
    }

    fn apply_data_version(
        &mut self,
        new_data_version: Option<&ArtifactVersion>,
    ) -> Result<()> {
        match self {
            DeserializedArtifactSource::File { .. } => {
                bail!("cannot apply data version to `file` source")
            }
            DeserializedArtifactSource::Fake { data_version, .. } => {
                *data_version = new_data_version.cloned();
                Ok(())
            }
            DeserializedArtifactSource::CompositeHost { .. } => {
                bail!(
                    "cannot yet apply data version to `composite_host` source"
                )
            }
            DeserializedArtifactSource::CompositeRot { .. } => {
                bail!("cannot yet apply data version to `composite_rot` source")
            }
            DeserializedArtifactSource::CompositeControlPlane { .. } => {
                bail!(
                    "cannot yet apply data version to `composite_control_plane` source"
                )
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeserializedFileArtifactSource {
    File {
        path: Utf8PathBuf,
    },
    Fake {
        #[serde(deserialize_with = "deserialize_byte_size")]
        size: u64,
    },
}

impl DeserializedFileArtifactSource {
    fn is_fake(&self) -> bool {
        matches!(self, DeserializedFileArtifactSource::Fake { .. })
    }

    fn with_entry<F, T>(&self, fake_attr: FakeDataAttributes, f: F) -> Result<T>
    where
        F: FnOnce(CompositeEntry<'_>) -> Result<T>,
    {
        let (data, mtime_source) = match self {
            DeserializedFileArtifactSource::File { path } => {
                let data = std::fs::read(path)
                    .with_context(|| format!("failed to read {path}"))?;
                // For now, always use the current time as the source. (Maybe
                // change this to use the mtime on disk in the future?)
                (data, MtimeSource::Now)
            }
            DeserializedFileArtifactSource::Fake { size } => {
                (fake_attr.make_data(*size as usize), MtimeSource::Zero)
            }
        };
        let entry = CompositeEntry { data: &data, mtime_source };
        f(entry)
    }

    fn apply_size_delta(&mut self, size_delta: i64) -> Result<()> {
        match self {
            DeserializedFileArtifactSource::File { .. } => {
                bail!("cannot apply size delta to `file` source")
            }
            DeserializedFileArtifactSource::Fake { size } => {
                *size = (*size).saturating_add_signed(size_delta);
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeserializedControlPlaneZoneSource {
    File {
        path: Utf8PathBuf,
        #[serde(skip_serializing_if = "Option::is_none")]
        file_name: Option<String>,
    },
    #[serde(rename_all = "snake_case")]
    Fake {
        artifact_name: String,
        file_name: String,
        #[serde(deserialize_with = "deserialize_byte_size")]
        size: u64,
    },
}

impl DeserializedControlPlaneZoneSource {
    fn is_fake(&self) -> bool {
        matches!(self, DeserializedControlPlaneZoneSource::Fake { .. })
    }

    fn with_name_and_entry<F, T>(
        &self,
        version: &ArtifactVersion,
        f: F,
    ) -> Result<T>
    where
        F: FnOnce(&str, CompositeEntry<'_>) -> Result<T>,
    {
        let (name, data, mtime_source) = match self {
            DeserializedControlPlaneZoneSource::File { path, file_name } => {
                let data = std::fs::read(path)
                    .with_context(|| format!("failed to read {path}"))?;
                let name = file_name
                    .as_deref()
                    .or_else(|| path.file_name())
                    .with_context(|| {
                        format!("zone path missing file name: {path}")
                    })?;
                // For now, always use the current time as the source. (Maybe
                // change this to use the mtime on disk in the future?)
                (name.to_owned(), data, MtimeSource::Now)
            }
            DeserializedControlPlaneZoneSource::Fake {
                artifact_name,
                file_name,
                size,
            } => {
                use flate2::{Compression, write::GzEncoder};
                use tufaceous_brand_metadata::{
                    ArchiveType, LayerInfo, Metadata,
                };

                let mut tar = tar::Builder::new(GzEncoder::new(
                    Vec::new(),
                    Compression::fast(),
                ));

                let metadata = Metadata::new(ArchiveType::Layer(LayerInfo {
                    pkg: artifact_name.clone(),
                    version: version.clone(),
                }));
                metadata.append_to_tar(&mut tar, 0)?;

                let mut h = tar::Header::new_ustar();
                h.set_entry_type(tar::EntryType::Regular);
                h.set_path("fake")?;
                h.set_mode(0o444);
                h.set_size(*size);
                h.set_mtime(0);
                h.set_cksum();
                tar.append(
                    &h,
                    make_filler_text(artifact_name, version, *size as usize)
                        .as_slice(),
                )?;

                let data = tar.into_inner()?.finish()?;
                (file_name.clone(), data, MtimeSource::Zero)
            }
        };
        let entry = CompositeEntry { data: &data, mtime_source };
        f(&name, entry)
    }

    fn apply_size_delta(&mut self, size_delta: i64) -> Result<()> {
        match self {
            DeserializedControlPlaneZoneSource::File { .. } => {
                bail!("cannot apply size delta to `file` source")
            }
            DeserializedControlPlaneZoneSource::Fake { size, .. } => {
                (*size) = (*size).saturating_add_signed(size_delta);
                Ok(())
            }
        }
    }
}
/// A change to apply to a manifest.
#[derive(Clone, Debug)]
pub enum ManifestTweak {
    /// Update the system version.
    SystemVersion(Version),

    /// Update the versions for this artifact.
    ArtifactVersion { kind: KnownArtifactKind, version: ArtifactVersion },

    /// Update the size of this fake artifact.
    ArtifactSize { kind: KnownArtifactKind, size_delta: i64 },

    /// Update the data version of this fake artifact.
    ///
    /// This version is typically the same as the artifact version, but it can
    /// be changed for testing purposes.
    ArtifactDataVersion {
        kind: KnownArtifactKind,
        /// Setting this to `None` resets the data version to the artifact
        /// version.
        data_version: Option<ArtifactVersion>,
    },
}

fn deserialize_byte_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Attempt to deserialize the size as either a string or an integer.

    struct Visitor;

    impl serde::de::Visitor<'_> for Visitor {
        type Value = u64;

        fn expecting(
            &self,
            formatter: &mut std::fmt::Formatter,
        ) -> std::fmt::Result {
            formatter
                .write_str("a string representing a byte size or an integer")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            parse_size(value).map_err(|_| {
                serde::de::Error::invalid_value(
                    serde::de::Unexpected::Str(value),
                    &self,
                )
            })
        }

        // TOML uses i64, not u64
        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(value as u64)
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(value)
        }
    }

    deserializer.deserialize_any(Visitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ensure that the fake manifest roundtrips after serialization and
    // deserialization.
    #[test]
    fn fake_roundtrip() {
        let manifest = DeserializedManifest::fake();
        let toml = toml::to_string(&manifest).unwrap();
        let deserialized = DeserializedManifest::from_str(&toml)
            .expect("fake manifest is a valid manifest");
        assert_eq!(manifest, deserialized);
    }
}
