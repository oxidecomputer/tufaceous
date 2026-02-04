// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use camino::Utf8Path;
use tufaceous::ExpirationEnforcement;
use tufaceous::RepositoryLoader;
use tufaceous::TrustStoreBehavior;
use tufaceous::error::Error;
use tufaceous_artifact::Artifacts;
use tufaceous_artifact::KnownArtifactTags;
use tufaceous_artifact::OsBoard;
use tufaceous_artifact::OsPhase1Tags;
use tufaceous_artifact::OsPhase2Tags;
use tufaceous_artifact::OsVariant;
use tufaceous_artifact::RotBootloaderTags;
use tufaceous_artifact::RotSlot;
use tufaceous_artifact::RotTags;
use tufaceous_artifact::Sign;
use tufaceous_artifact::SpTags;
use tufaceous_artifact::ZoneTags;

#[tokio::test]
async fn v1_fake() -> Result<(), Error> {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let path = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/v1-fake.zip");

    let repo = RepositoryLoader::new()
        .expiration_enforcement(ExpirationEnforcement::Unsafe)
        .trust_store_behavior(TrustStoreBehavior::UnsafeBlindFaith)
        .v1_compatibility(true)
        .load_zip_path(path, &log)
        .await?;
    let parallelism = std::thread::available_parallelism().unwrap().get();
    repo.verify_targets(parallelism).await?;

    // We expect to see one of each of these artifacts:
    let mut expected = vec![
        KnownArtifactTags::InstallinatorDocument,
        KnownArtifactTags::MeasurementCorpus,
    ];
    for os_variant in [OsVariant::Host, OsVariant::Recovery] {
        for os_board in [OsBoard::Cosmo, OsBoard::Gimlet] {
            expected.push(OsPhase1Tags { os_board, os_variant }.into());
        }
        expected.push(OsPhase2Tags { os_variant }.into());
    }
    for rot_sign in ["sign-gimlet", "sign-psc", "sign-switch"] {
        for rot_slot in [RotSlot::A, RotSlot::B] {
            expected.push(
                RotTags {
                    rot_board: "SimRot".into(),
                    rot_sign: Sign(Some(rot_sign.into())),
                    rot_slot,
                }
                .into(),
            );
        }
        expected.push(
            RotBootloaderTags {
                rot_board: "SimRot".into(),
                rot_sign: Sign(Some(rot_sign.into())),
            }
            .into(),
        );
    }
    for sp_board in ["SimGimletSp", "SimPscSp", "SimSidecarSp"] {
        expected.push(SpTags { sp_board: sp_board.into() }.into());
    }
    for zone_name in ["zone-1", "zone-2"] {
        expected.push(ZoneTags { zone_name: zone_name.into() }.into());
    }
    let seen = expected
        .into_iter()
        .map(|tags| repo.artifacts().get(tags).unwrap().clone())
        .collect::<Artifacts>();
    // And there should be no unexpected artifacts:
    assert_eq!(&seen, repo.artifacts());

    Ok(())
}

#[tokio::test]
#[should_panic(expected = "target artifacts-v2.json not found")]
async fn v1_fake_without_compat() {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let path = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/v1-fake.zip");

    let _ = RepositoryLoader::new()
        .expiration_enforcement(ExpirationEnforcement::Unsafe)
        .trust_store_behavior(TrustStoreBehavior::UnsafeBlindFaith)
        .v1_compatibility(false)
        .load_zip_path(path, &log)
        .await
        .map_err(|error| error.to_string())
        .unwrap();
}
