// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;

use tufaceous_artifact::ArtifactSet;
use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::OsVariant;
use tufaceous_artifact::RotBootloaderTags;
use tufaceous_artifact::RotKeyTableHash;
use tufaceous_artifact::RotSlot;
use tufaceous_artifact::RotTags;
use tufaceous_artifact::SpTags;

use crate::edit::generate_installinator_document;
use crate::edit::input::Input;
use crate::edit::source::BytesSource;
use crate::error::Error;
use crate::schema::ArtifactSchema;

const FAKE_SIGN: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

const FAKE_ZONES: [(&str, &str); 11] = [
    ("clickhouse", "clickhouse.tar.gz"),
    ("clickhouse_keeper", "clickhouse_keeper.tar.gz"),
    ("clickhouse_server", "clickhouse_server.tar.gz"),
    ("cockroachdb", "cockroachdb.tar.gz"),
    ("crucible-zone", "crucible.tar.gz"),
    ("crucible-pantry-zone", "crucible_pantry.tar.gz"),
    ("external-dns", "external_dns.tar.gz"),
    ("internal-dns", "internal_dns.tar.gz"),
    ("ntp", "ntp.tar.gz"),
    ("nexus", "nexus.tar.gz"),
    ("oximeter", "oximeter.tar.gz"),
];

pub trait ArtifactSetExt: Sized {
    fn fake(version: ArtifactVersion) -> Result<Self, Error>;
}

impl ArtifactSetExt for ArtifactSet {
    fn fake(version: ArtifactVersion) -> Result<Self, Error> {
        let mut artifacts = HashMap::new();
        for input in Input::fake(&version, None)? {
            for output in input.outputs()? {
                artifacts.extend(output.into_artifact());
            }
        }
        artifacts.extend(
            generate_installinator_document(
                artifacts.iter().map(|(target_name, artifact)| {
                    (
                        ArtifactSchema {
                            target_name: target_name.clone(),
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
        Ok(artifacts.into_values().collect())
    }
}

impl Input<BytesSource> {
    pub(crate) fn fake(
        version: &ArtifactVersion,
        interior_version: Option<&ArtifactVersion>,
    ) -> Result<Vec<Self>, Error> {
        let mut inputs = Vec::new();
        for hashes in [4, 16] {
            inputs.push(Self::fake_measurement_corpus(
                hashes,
                version.clone(),
                interior_version,
            )?);
        }
        for variant in [OsVariant::Host, OsVariant::Recovery] {
            inputs.push(Self::fake_os_images(
                variant,
                version.clone(),
                interior_version,
            ));
        }
        for slot in [RotSlot::A, RotSlot::B] {
            inputs.push(Self::fake_rot_archive(
                RotTags {
                    rot_board: "SimRot".into(),
                    rot_rkth: RotKeyTableHash(Some(FAKE_SIGN.into())),
                    rot_slot: slot,
                },
                version.clone(),
                interior_version,
            )?);
        }
        inputs.push(Self::fake_rot_bootloader_archive(
            RotBootloaderTags {
                rot_board: "SimRot".into(),
                rot_rkth: RotKeyTableHash(Some(FAKE_SIGN.into())),
            },
            version.clone(),
            interior_version,
        )?);
        for board in ["SimGimletSp", "SimCosmoSp", "SimSidecarSp", "SimPscSp"] {
            inputs.push(Self::fake_sp_archive(
                SpTags { sp_board: board.into() },
                version.clone(),
                interior_version,
            )?);
        }
        for (zone_name, file_name) in FAKE_ZONES {
            inputs.push(Self::fake_zone_image(
                zone_name.into(),
                file_name.into(),
                version.clone(),
                interior_version.cloned(),
            )?);
        }
        Ok(inputs)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use semver::Version;
    use tufaceous_artifact::ArtifactSet;
    use tufaceous_artifact::ArtifactVersion;

    use crate::Repository;
    use crate::edit::ArtifactSetExt;

    #[tokio::test]
    async fn fake_artifacts_equals_fake_repo() {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        let system_version = Version::new(1, 0, 0);
        let version = ArtifactVersion::new(system_version.to_string()).unwrap();

        let artifacts = ArtifactSet::fake(version).unwrap();
        // sleep 1 second to ensure any embedded timestamps would be different.
        // we could ostensibly use `tokio::time::Instant` throughout the code
        // base but that wouldn't take into account third-party libraries we use
        // to generate fake artifacts.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let repo = Repository::fake(system_version, &log).await.unwrap();
        assert_eq!(&artifacts, repo.artifacts());
    }
}
