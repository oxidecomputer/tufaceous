// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::Artifacts;
use tufaceous_artifact::OsVariant;
use tufaceous_artifact::RotBootloaderTags;
use tufaceous_artifact::RotSlot;
use tufaceous_artifact::RotTags;
use tufaceous_artifact::Sign;
use tufaceous_artifact::SpTags;

use crate::edit::generate_installinator_document;
use crate::edit::input::Input;
use crate::edit::source::BytesSource;
use crate::error::Error;
use crate::schema::ArtifactSchema;

pub trait ArtifactsExt: Sized {
    fn fake(version: ArtifactVersion) -> Result<Self, Error>;
}

impl ArtifactsExt for Artifacts {
    fn fake(version: ArtifactVersion) -> Result<Self, Error> {
        let mut artifacts = Artifacts::default();
        for input in Input::fake(&version)? {
            for output in input.outputs() {
                artifacts.extend(output.into_artifact());
            }
        }
        artifacts.extend(
            generate_installinator_document(
                artifacts.iter().map(|artifact| {
                    (
                        ArtifactSchema {
                            target_name: artifact.target_name.clone(),
                            version: artifact.version.clone(),
                            tags: artifact.tags.clone(),
                        },
                        &artifact.hash,
                    )
                }),
                version,
            )?
            .into_artifact(),
        );
        Ok(artifacts)
    }
}

impl Input<BytesSource> {
    pub(crate) fn fake(version: &ArtifactVersion) -> Result<Vec<Self>, Error> {
        let mut inputs = Vec::new();
        for hashes in [4, 16] {
            inputs
                .push(Self::fake_measurement_corpus(hashes, version.clone())?);
        }
        for variant in [OsVariant::Host, OsVariant::Recovery] {
            inputs.push(Self::fake_os_images(variant, version.clone()));
        }
        for slot in [RotSlot::A, RotSlot::B] {
            inputs.push(Self::fake_rot_archive(
                RotTags {
                    rot_board: "fake-rot".into(),
                    rot_sign: Sign::UNSIGNED,
                    rot_slot: slot,
                },
                version.clone(),
            )?);
        }
        inputs.push(Self::fake_rot_bootloader_archive(
            RotBootloaderTags {
                rot_board: "fake-rot".into(),
                rot_sign: Sign::UNSIGNED,
            },
            version.clone(),
        )?);
        for board in ["fake-gimlet", "fake-cosmo", "fake-sidecar", "fake-psc"] {
            inputs.push(Self::fake_sp_archive(
                SpTags { sp_board: board.into() },
                version.clone(),
            )?);
        }
        for name in ["zone1", "zone2"] {
            inputs.push(Self::fake_zone_image(name.into(), version.clone())?);
        }
        Ok(inputs)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use semver::Version;
    use tufaceous_artifact::ArtifactVersion;
    use tufaceous_artifact::Artifacts;

    use crate::Repository;
    use crate::edit::ArtifactsExt;

    #[tokio::test]
    async fn fake_artifacts_equals_fake_repo() {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let system_version = Version::new(1, 0, 0);
        let version = ArtifactVersion::new(system_version.to_string()).unwrap();

        let artifacts = Artifacts::fake(version).unwrap();
        // sleep 1 second to ensure any embedded timestamps would be different.
        // we could ostensibly use `tokio::time::Instant` throughout the code
        // base but that wouldn't take into account third-party libraries we use
        // to generate fake artifacts.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let repo = Repository::fake(system_version, &log).await.unwrap();
        assert_eq!(&artifacts, repo.artifacts());
    }
}
