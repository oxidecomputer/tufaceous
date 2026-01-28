// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
use std::path::Path;

use bytes::BufMut;
use bytes::BytesMut;
use camino::Utf8Path;
use camino::Utf8PathBuf;
use flate2::read::GzDecoder;
use futures_util::TryStreamExt;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::OsVariant;

use crate::COSMO_PHASE_1_PATH;
use crate::GIMLET_PHASE_1_PATH;
use crate::PHASE_2_PATH;
use crate::edit::KIB;
use crate::edit::MIB;
use crate::edit::OXIDE_BOOT_MAGIC;
use crate::edit::input::Input;
use crate::edit::source::BytesSource;
use crate::edit::source::FileSource;
use crate::edit::source::TargetSource;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::error::try_path;

impl Input<TargetSource<'static>> {
    pub(crate) async fn os_images(
        os_variant: OsVariant,
        dir: &Utf8Path,
        phase_2: Option<FileSource>,
        version: ArtifactVersion,
    ) -> Result<Self, Error> {
        let cosmo_phase_1 =
            FileSource::open(dir.join(COSMO_PHASE_1_PATH)).await?.into();
        let gimlet_phase_1 =
            FileSource::open(dir.join(GIMLET_PHASE_1_PATH)).await?.into();
        let phase_2 = match phase_2 {
            Some(phase_2) => phase_2,
            None => FileSource::open(dir.join(PHASE_2_PATH)).await?,
        };

        // If `os.tar.gz` is present, read the `image/*.txt` files from it
        // as extra sources. Stop once we get to `zfs.img`, which comes after
        // the additional metadata. (If a GzDecoder was seekable we could
        // conceivably skip past any files we don't want to read, but alas.)
        // https://github.com/oxidecomputer/helios/blob/f145457f6ccb13a139b8d93408b9b4de5db57bd6/tools/helios-build/src/main.rs#L1881-L1885
        let tarball_path = dir.join("os.tar.gz");
        let mut extra_targets = match tokio::fs::File::open(&tarball_path).await
        {
            Ok(file) => {
                let file = file.into_std().await;
                tokio::task::spawn_blocking(move || {
                    read_os_tarball_metadata_blocking(file, tarball_path)
                })
                .await??
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                // We might be reading from an unpacked Tufaceous archive; look
                // for any `*.txt` files and include them.
                let mut extra_targets = BTreeMap::new();
                let mut read_dir = crate::util::read_dir(dir.into()).await?;
                while let Some(entry) = read_dir.try_next().await? {
                    if entry.path().extension() != Some("txt") {
                        continue;
                    }
                    let file_name = entry.file_name().to_owned();
                    let source = FileSource::open(entry.into_path()).await?;
                    extra_targets.insert(file_name, source.into());
                }
                extra_targets
            }
            Err(source) => {
                return Err(ErrorKind::OpenFile {
                    source,
                    path: Some(tarball_path),
                }
                .into());
            }
        };
        for path in ["unix.z", "cpio.z"] {
            let source = FileSource::open(dir.join(path)).await?;
            extra_targets.insert(path.into(), source.into());
        }

        Ok(Self::OsImages {
            cosmo_phase_1,
            gimlet_phase_1,
            phase_2: phase_2.into(),
            extra_targets,
            os_variant,
            version,
        })
    }

    pub(crate) async fn guess_os_images(
        path: &Utf8Path,
        version: &ArtifactVersion,
    ) -> Option<Result<Self, Error>> {
        let phase_2_path = path.join(PHASE_2_PATH);
        let mut file = File::open(&phase_2_path).await.ok()?;
        // Read the header block from the image and guess whether it's a
        // recovery image based on the image name.
        let mut buf = [0; 4096];
        file.read_exact(&mut buf).await.ok()?;
        if !buf.starts_with(&OXIDE_BOOT_MAGIC) {
            return None;
        }
        // see https://github.com/oxidecomputer/boot-image-tools/blob/main/src/diskimage.rs
        let image_name = &buf[200..328];
        let variant = if image_name.starts_with(b"recovery") {
            OsVariant::Recovery
        } else {
            OsVariant::Host
        };

        let phase_2 = FileSource::from_file(file, phase_2_path);
        Some(
            Self::os_images(variant, path, Some(phase_2), version.clone())
                .await,
        )
    }
}

fn read_os_tarball_metadata_blocking(
    file: std::fs::File,
    tarball_path: Utf8PathBuf,
) -> Result<BTreeMap<String, TargetSource<'static>>, Error> {
    let mut metadata = BTreeMap::new();
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    for entry in try_path!(archive.entries(), ReadFile, tarball_path) {
        let mut entry = try_path!(entry, ReadFile, tarball_path);
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = try_path!(entry.path(), ReadFile, tarball_path);
        let Some(parent) = path.parent() else { continue };
        if parent != "image" {
            continue;
        }
        let Some(extension) = path.extension() else { continue };
        if extension != "txt" {
            continue;
        }
        let file_name = Path::new(
            path.file_name()
                .expect("a path with an extension must have a file name"),
        );
        if file_name == "zfs.img" {
            break;
        }
        let file_name = try_path!(
            Utf8PathBuf::try_from(file_name.to_owned())
                .map_err(camino::FromPathBufError::into_io_error),
            ReadFile,
            tarball_path
        );
        let mut writer = BytesMut::new().writer();
        try_path!(
            std::io::copy(&mut entry, &mut writer),
            ReadFile,
            tarball_path
        );
        let source = BytesSource::new(writer.into_inner().freeze());
        metadata.insert(file_name.into(), source.into());
    }
    Ok(metadata)
}

impl Input<BytesSource> {
    pub(crate) fn fake_os_images(
        os_variant: OsVariant,
        version: ArtifactVersion,
    ) -> Self {
        let cosmo_phase_1 = BytesSource::fake_padded(
            format!("cosmo {os_variant} OS phase 1 image version {version}\n"),
            MIB,
        );
        let gimlet_phase_1 = BytesSource::fake_padded(
            format!("gimlet {os_variant} OS phase 1 image version {version}\n"),
            MIB,
        );
        let phase_2 = BytesSource::fake_padded(
            format!("{os_variant} OS phase 2 image version {version}\n"),
            4 * MIB,
        );

        let mut extra_targets = BTreeMap::new();
        extra_targets.insert(
            String::from("unix.z"),
            BytesSource::fake_padded(
                format!("{os_variant} OS unix.z version {version}\n"),
                64 * KIB,
            ),
        );
        extra_targets.insert(
            String::from("cpio.z"),
            BytesSource::fake_padded(
                format!("{os_variant} OS cpio.z version {version}\n"),
                256 * KIB,
            ),
        );

        Self::OsImages {
            cosmo_phase_1,
            gimlet_phase_1,
            phase_2,
            extra_targets,
            os_variant,
            version,
        }
    }
}
