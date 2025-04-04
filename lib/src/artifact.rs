// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::io::{self, BufReader, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use buf_list::BufList;
use bytes::Bytes;
use camino::Utf8PathBuf;
use fs_err::File;
use tufaceous_artifact::{ArtifactKind, ArtifactVersion};
use tufaceous_brand_metadata::Metadata;

mod composite;

pub use composite::CompositeControlPlaneArchiveBuilder;
pub use composite::CompositeEntry;
pub use composite::CompositeHostArchiveBuilder;
pub use composite::CompositeRotArchiveBuilder;
pub use composite::MtimeSource;

use crate::assemble::ArtifactDeploymentUnits;

/// The location a artifact will be obtained from.
#[derive(Clone, Debug)]
pub enum ArtifactSource {
    File(Utf8PathBuf),
    Memory(BufList),
    // We might need to support downloading data over HTTP as well
}

/// Describes a new artifact to be added.
pub struct AddArtifact {
    kind: ArtifactKind,
    name: String,
    version: ArtifactVersion,
    source: ArtifactSource,
    deployment_units: ArtifactDeploymentUnits,
}

impl AddArtifact {
    /// Creates an [`AddArtifact`] from the provided source.
    pub fn new(
        kind: ArtifactKind,
        name: String,
        version: ArtifactVersion,
        source: ArtifactSource,
        deployment_units: ArtifactDeploymentUnits,
    ) -> Self {
        Self { kind, name, version, source, deployment_units }
    }

    /// Creates an [`AddArtifact`] from the path, name and version.
    ///
    /// If the name is `None`, it is derived from the filename of the path
    /// without matching extensions.
    pub fn from_path(
        kind: ArtifactKind,
        name: Option<String>,
        version: ArtifactVersion,
        path: Utf8PathBuf,
    ) -> Result<Self> {
        let name = match name {
            Some(name) => name,
            None => path
                .file_name()
                .context("artifact path is a directory")?
                .split('.')
                .next()
                .expect("str::split has at least 1 element")
                .to_owned(),
        };

        // TODO: In the future, it would be nice to extract the deployment units
        // from the file. But that would require parsing the file, and the code
        // for that lives in Omicron under update-common.
        Ok(Self {
            kind,
            name,
            version,
            source: ArtifactSource::File(path),
            deployment_units: ArtifactDeploymentUnits::Unknown,
        })
    }

    /// Returns the kind of artifact this is.
    pub fn kind(&self) -> &ArtifactKind {
        &self.kind
    }

    /// Returns the name of the new artifact.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the version of the new artifact.
    pub fn version(&self) -> &ArtifactVersion {
        &self.version
    }

    /// Returns the source for this artifact.
    pub fn source(&self) -> &ArtifactSource {
        &self.source
    }

    /// Returns information about deployment units for this artifact.
    pub fn deployment_units(&self) -> &ArtifactDeploymentUnits {
        &self.deployment_units
    }

    /// Writes this artifact to the specified writer.
    pub(crate) fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match &self.source {
            ArtifactSource::File(path) => {
                let mut reader = File::open(path)?;
                std::io::copy(&mut reader, writer)?;
            }
            ArtifactSource::Memory(buf_list) => {
                for chunk in buf_list {
                    writer.write_all(chunk)?;
                }
            }
        }

        Ok(())
    }
}

pub(crate) fn make_filler_text(
    // This can be either the artifact kind, or the deployment unit kind for a
    // composite artifact.
    kind: &str,
    version: &ArtifactVersion,
    length: usize,
) -> Vec<u8> {
    // Add the kind and version to the filler text first. This ensures that
    // hashes are unique by kind and version.
    let mut out = Vec::with_capacity(length);
    out.extend_from_slice(kind.as_bytes());
    out.extend_from_slice(b":");
    out.extend_from_slice(version.as_str().as_bytes());
    out.extend_from_slice(b":");

    let remaining = length.saturating_sub(out.len());
    out.extend(
        std::iter::repeat(FILLER_TEXT).flatten().copied().take(remaining),
    );

    out
}

/// Represents host phase images.
///
/// The host and trampoline artifacts are actually tarballs, with phase 1 and
/// phase 2 images inside them. This code extracts those images out of the
/// tarballs.
#[derive(Clone, Debug)]
pub struct HostPhaseImages {
    pub phase_1: Bytes,
    pub phase_2: Bytes,
}

impl HostPhaseImages {
    pub fn extract<R: io::BufRead>(reader: R) -> Result<Self> {
        let mut phase_1 = Vec::new();
        let mut phase_2 = Vec::new();
        Self::extract_into(
            reader,
            io::Cursor::<&mut Vec<u8>>::new(&mut phase_1),
            io::Cursor::<&mut Vec<u8>>::new(&mut phase_2),
        )?;
        Ok(Self { phase_1: phase_1.into(), phase_2: phase_2.into() })
    }

    pub fn extract_into<R: io::BufRead, W: io::Write>(
        reader: R,
        phase_1: W,
        phase_2: W,
    ) -> Result<()> {
        let uncompressed = flate2::bufread::GzDecoder::new(reader);
        let mut archive = tar::Archive::new(uncompressed);

        let mut oxide_json_found = false;
        let mut phase_1_writer = Some(phase_1);
        let mut phase_2_writer = Some(phase_2);
        for entry in archive
            .entries()
            .context("error building list of entries from archive")?
        {
            let entry = entry.context("error reading entry from archive")?;
            let path = entry
                .header()
                .path()
                .context("error reading path from archive")?;
            if path == Path::new(OXIDE_JSON_FILE_NAME) {
                let json_bytes = read_entry(entry, OXIDE_JSON_FILE_NAME)?;
                let metadata: Metadata =
                    serde_json::from_slice(&json_bytes).with_context(|| {
                        format!(
                            "error deserializing JSON from {OXIDE_JSON_FILE_NAME}"
                        )
                    })?;
                if !metadata.is_os() {
                    bail!(
                        "unexpected archive type: expected os, found {:?}",
                        metadata.archive_type(),
                    )
                }
                oxide_json_found = true;
            } else if path == Path::new(HOST_PHASE_1_FILE_NAME) {
                if let Some(phase_1) = phase_1_writer.take() {
                    read_entry_into(entry, HOST_PHASE_1_FILE_NAME, phase_1)?;
                }
            } else if path == Path::new(HOST_PHASE_2_FILE_NAME) {
                if let Some(phase_2) = phase_2_writer.take() {
                    read_entry_into(entry, HOST_PHASE_2_FILE_NAME, phase_2)?;
                }
            }

            if oxide_json_found
                && phase_1_writer.is_none()
                && phase_2_writer.is_none()
            {
                break;
            }
        }

        let mut not_found = Vec::new();
        if !oxide_json_found {
            not_found.push(OXIDE_JSON_FILE_NAME);
        }

        // If we didn't `.take()` the writer out of the options, we never saw
        // the expected phase1/phase2 filenames.
        if phase_1_writer.is_some() {
            not_found.push(HOST_PHASE_1_FILE_NAME);
        }
        if phase_2_writer.is_some() {
            not_found.push(HOST_PHASE_2_FILE_NAME);
        }

        if !not_found.is_empty() {
            bail!("required files not found: {}", not_found.join(", "))
        }

        Ok(())
    }
}

fn read_entry<R: io::Read>(
    entry: tar::Entry<R>,
    file_name: &str,
) -> Result<Bytes> {
    let mut buf = Vec::new();
    read_entry_into(entry, file_name, io::Cursor::new(&mut buf))?;
    Ok(buf.into())
}

fn read_entry_into<R: io::Read, W: io::Write>(
    mut entry: tar::Entry<R>,
    file_name: &str,
    mut out: W,
) -> Result<()> {
    let entry_type = entry.header().entry_type();
    if entry_type != tar::EntryType::Regular {
        bail!("for {file_name}, expected regular file, found {entry_type:?}");
    }
    io::copy(&mut entry, &mut out)
        .with_context(|| format!("error reading {file_name} from archive"))?;
    Ok(())
}

/// Represents RoT A/B hubris archives.
///
/// RoT artifacts are actually tarballs, with both A and B hubris archives
/// inside them. This code extracts those archives out of the tarballs.
#[derive(Clone, Debug)]
pub struct RotArchives {
    pub archive_a: Bytes,
    pub archive_b: Bytes,
}

impl RotArchives {
    pub fn extract<R: io::BufRead>(reader: R) -> Result<Self> {
        let mut archive_a = Vec::new();
        let mut archive_b = Vec::new();
        Self::extract_into(
            reader,
            io::Cursor::<&mut Vec<u8>>::new(&mut archive_a),
            io::Cursor::<&mut Vec<u8>>::new(&mut archive_b),
        )?;
        Ok(Self { archive_a: archive_a.into(), archive_b: archive_b.into() })
    }

    pub fn extract_into<R: io::BufRead, W: io::Write>(
        reader: R,
        archive_a: W,
        archive_b: W,
    ) -> Result<()> {
        let uncompressed = flate2::bufread::GzDecoder::new(reader);
        let mut archive = tar::Archive::new(uncompressed);

        let mut oxide_json_found = false;
        let mut archive_a_writer = Some(archive_a);
        let mut archive_b_writer = Some(archive_b);
        for entry in archive
            .entries()
            .context("error building list of entries from archive")?
        {
            let entry = entry.context("error reading entry from archive")?;
            let path = entry
                .header()
                .path()
                .context("error reading path from archive")?;
            if path == Path::new(OXIDE_JSON_FILE_NAME) {
                let json_bytes = read_entry(entry, OXIDE_JSON_FILE_NAME)?;
                let metadata: Metadata =
                    serde_json::from_slice(&json_bytes).with_context(|| {
                        format!(
                            "error deserializing JSON from {OXIDE_JSON_FILE_NAME}"
                        )
                    })?;
                if !metadata.is_rot() {
                    bail!(
                        "unexpected archive type: expected rot, found {:?}",
                        metadata.archive_type(),
                    )
                }
                oxide_json_found = true;
            } else if path == Path::new(ROT_ARCHIVE_A_FILE_NAME) {
                if let Some(archive_a) = archive_a_writer.take() {
                    read_entry_into(entry, ROT_ARCHIVE_A_FILE_NAME, archive_a)?;
                }
            } else if path == Path::new(ROT_ARCHIVE_B_FILE_NAME) {
                if let Some(archive_b) = archive_b_writer.take() {
                    read_entry_into(entry, ROT_ARCHIVE_B_FILE_NAME, archive_b)?;
                }
            }

            if oxide_json_found
                && archive_a_writer.is_none()
                && archive_b_writer.is_none()
            {
                break;
            }
        }

        let mut not_found = Vec::new();
        if !oxide_json_found {
            not_found.push(OXIDE_JSON_FILE_NAME);
        }

        // If we didn't `.take()` the writer out of the options, we never saw
        // the expected A/B filenames.
        if archive_a_writer.is_some() {
            not_found.push(ROT_ARCHIVE_A_FILE_NAME);
        }
        if archive_b_writer.is_some() {
            not_found.push(ROT_ARCHIVE_B_FILE_NAME);
        }

        if !not_found.is_empty() {
            bail!("required files not found: {}", not_found.join(", "))
        }

        Ok(())
    }
}

/// Represents control plane zone images.
///
/// The control plane artifact is actually a tarball that contains a set of zone
/// images. This code extracts those images out of the tarball.
#[derive(Clone, Debug)]
pub struct ControlPlaneZoneImages {
    pub zones: Vec<(String, Bytes)>,
}

impl ControlPlaneZoneImages {
    pub fn extract<R: io::Read>(reader: R) -> Result<Self> {
        let mut zones = Vec::new();
        Self::extract_into(reader, |name, reader| {
            let mut buf = Vec::new();
            io::copy(reader, &mut buf)?;
            zones.push((name, buf.into()));
            Ok(())
        })?;
        Ok(Self { zones })
    }

    pub fn extract_into<R, F>(reader: R, mut handler: F) -> Result<()>
    where
        R: io::Read,
        F: FnMut(String, &mut dyn io::Read) -> Result<()>,
    {
        let uncompressed =
            flate2::bufread::GzDecoder::new(BufReader::new(reader));
        let mut archive = tar::Archive::new(uncompressed);

        let mut oxide_json_found = false;
        let mut zone_found = false;
        for entry in archive
            .entries()
            .context("error building list of entries from archive")?
        {
            let mut entry =
                entry.context("error reading entry from archive")?;
            let path = entry
                .header()
                .path()
                .context("error reading path from archive")?;
            if path == Path::new(OXIDE_JSON_FILE_NAME) {
                let json_bytes = read_entry(entry, OXIDE_JSON_FILE_NAME)?;
                let metadata: Metadata =
                    serde_json::from_slice(&json_bytes).with_context(|| {
                        format!(
                            "error deserializing JSON from {OXIDE_JSON_FILE_NAME}"
                        )
                    })?;
                if !metadata.is_control_plane() {
                    bail!(
                        "unexpected archive type: expected control_plane, found {:?}",
                        metadata.archive_type(),
                    )
                }
                oxide_json_found = true;
            } else if path.starts_with(CONTROL_PLANE_ARCHIVE_ZONE_DIRECTORY) {
                if let Some(name) = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string())
                {
                    handler(name, &mut entry)?;
                }
                zone_found = true;
            }
        }

        let mut not_found = Vec::new();
        if !oxide_json_found {
            not_found.push(OXIDE_JSON_FILE_NAME);
        }
        if !not_found.is_empty() {
            bail!("required files not found: {}", not_found.join(", "))
        }
        if !zone_found {
            bail!(
                "no zone images found in `{}/`",
                CONTROL_PLANE_ARCHIVE_ZONE_DIRECTORY
            );
        }

        Ok(())
    }
}

static FILLER_TEXT: &[u8; 16] = b"tufaceousfaketxt";
static OXIDE_JSON_FILE_NAME: &str = "oxide.json";
pub(crate) static HOST_PHASE_1_FILE_NAME: &str = "image/rom";
pub(crate) static HOST_PHASE_2_FILE_NAME: &str = "image/zfs.img";
pub(crate) static ROT_ARCHIVE_A_FILE_NAME: &str = "archive-a.zip";
pub(crate) static ROT_ARCHIVE_B_FILE_NAME: &str = "archive-b.zip";
static CONTROL_PLANE_ARCHIVE_ZONE_DIRECTORY: &str = "zones";
