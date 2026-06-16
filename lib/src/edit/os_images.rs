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

        let phase_2 =
            FileSource::from_file(file.into_std().await, phase_2_path);
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
            break;
        }
        let file_name = Path::new(
            path.file_name()
                .expect("a path with an extension must have a file name"),
        );
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
        interior_version: Option<&ArtifactVersion>,
    ) -> Self {
        let interior_version = interior_version.unwrap_or(&version);
        let cosmo_phase_1 = BytesSource::fake_padded(
            format!(
                "cosmo {os_variant} OS phase 1 image version {interior_version}\n"
            ),
            MIB,
        );
        let gimlet_phase_1 = BytesSource::fake_padded(
            format!(
                "gimlet {os_variant} OS phase 1 image version {interior_version}\n"
            ),
            MIB,
        );

        let mut phase_2_bytes = BytesMut::with_capacity(4096);
        phase_2_bytes.put(OXIDE_BOOT_MAGIC.as_slice()); // uint32_t odh_magic;
        phase_2_bytes.put_u32_le(2); // uint32_t odh_version;
        // The only defined ODH_FLAG is:
        //     #define ODH_FLAG_COMPRESSED 0x1
        // but we are not compressing any fake images. (Normally the host image
        // is "uncompressed" -- a raw ZFS image with compressed contents -- and
        // the recovery image is compressed.)
        phase_2_bytes.put_u64_le(0); // uint64_t odh_flags;
        phase_2_bytes.put_u64_le(4 * MIB); // uint64_t odh_data_size;
        phase_2_bytes.put_u64_le(4 * MIB); // uint64_t odh_image_size;
        phase_2_bytes.put_u64_le(1 << 32); // uint64_t odh_target_size;
        // #define OXBOOT_CSUMLEN_SHA256 32
        // uint8_t odh_sha256[OXBOOT_CSUMLEN_SHA256];
        phase_2_bytes.put(
            // head -c $((4 * 1024 * 1024)) </dev/zero | sha256sum
            b"\xbb\x9f\x8d\xf6\x14\x74\xd2\x5e\x71\xfa\x00\x72\x23\x18\xcd\x38\
            \x73\x96\xca\x17\x36\x60\x5e\x12\x48\x82\x1c\xc0\xde\x3d\x3a\xf8"
                .as_slice(),
        );
        // #define OXBOOT_DISK_DATASET_SIZE 128
        // char odh_dataset[OXBOOT_DISK_DATASET_SIZE];
        let end = phase_2_bytes.len() + 128;
        phase_2_bytes.put(b"rpool/ROOT/ramdisk".as_slice());
        phase_2_bytes.resize(end, 0);
        // #define OXBOOT_DISK_IMAGENAME_SIZE 128
        // char odh_imagename[OXBOOT_DISK_IMAGENAME_SIZE];
        phase_2_bytes.put(match os_variant {
            OsVariant::Host => "ci".as_bytes(),
            OsVariant::Recovery => "recovery".as_bytes(),
        });
        phase_2_bytes.put(" fake123/789fake 1986-12-28 01:23".as_bytes());
        // rest of header is zeroes, which will be written out by `fake_padded`
        let phase_2 = BytesSource::fake_padded(phase_2_bytes, 4096 + 4 * MIB);

        let mut extra_targets = BTreeMap::new();
        extra_targets.insert(
            String::from("unix.z"),
            BytesSource::fake_padded(
                format!("{os_variant} OS unix.z version {interior_version}\n"),
                64 * KIB,
            ),
        );
        extra_targets.insert(
            String::from("cpio.z"),
            BytesSource::fake_padded(
                format!("{os_variant} OS cpio.z version {interior_version}\n"),
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
