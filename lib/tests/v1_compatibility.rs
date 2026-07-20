// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;
use std::sync::Arc;

use camino::Utf8Path;
use futures_util::TryStreamExt;
use tufaceous::ExpirationEnforcement;
use tufaceous::RepositoryLoader;
use tufaceous::error::Error;
use tufaceous_artifact::ArtifactSet;
use tufaceous_artifact::InstallinatorDocument;
use tufaceous_artifact::KnownArtifactTags;
use tufaceous_artifact::OsBoard;
use tufaceous_artifact::OsPhase1Tags;
use tufaceous_artifact::OsPhase2Tags;
use tufaceous_artifact::OsVariant;
use tufaceous_artifact::RotBootloaderTags;
use tufaceous_artifact::RotKeyTableHash;
use tufaceous_artifact::RotSlot;
use tufaceous_artifact::RotTags;
use tufaceous_artifact::SpTags;
use tufaceous_artifact::ZoneTags;

#[tokio::test]
async fn v1_fake() -> Result<(), Error> {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let path = Utf8Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/v1-fake.zip");

    let repo = Arc::new(
        RepositoryLoader::new()
            .expiration_enforcement(ExpirationEnforcement::Unsafe)
            .unsafe_blindly_trust_repo()
            .v1_compatibility(true)
            .load_zip_path(path, &log)
            .await?,
    );
    let parallelism = std::thread::available_parallelism().unwrap().get();
    repo.verify_targets(parallelism).await?;

    // We expect to see one of each of these artifacts:
    let mut expected = vec![
        KnownArtifactTags::InstallinatorDocument,
        KnownArtifactTags::MeasurementCorpus,
    ];
    for os_variant in [OsVariant::Host, OsVariant::Recovery] {
        for os_board in [OsBoard::COSMO, OsBoard::GIMLET] {
            expected.push(OsPhase1Tags { os_board, os_variant }.into());
        }
        expected.push(OsPhase2Tags { os_variant }.into());
    }
    for rot_rkth in ["sign-gimlet", "sign-psc", "sign-switch"] {
        for rot_slot in [RotSlot::A, RotSlot::B] {
            expected.push(
                RotTags {
                    rot_board: "SimRot".into(),
                    rot_rkth: Some(RotKeyTableHash::new(rot_rkth)),
                    rot_slot,
                }
                .into(),
            );
        }
        expected.push(
            RotBootloaderTags {
                rot_board: "SimRot".into(),
                rot_rkth: Some(RotKeyTableHash::new(rot_rkth)),
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
        .iter()
        .map(|tags| repo.artifacts().get_only(tags).unwrap().clone())
        .collect::<ArtifactSet>();
    // And there should be no unexpected artifacts:
    assert_eq!(&seen, repo.artifacts());

    // The Installinator document should be regenerated to only reference
    // v2 artifacts.
    let mut hashes = repo
        .artifacts()
        .iter()
        .map(|artifact| artifact.hash)
        .collect::<BTreeSet<_>>();
    let artifact = repo
        .artifacts()
        .get_only(&KnownArtifactTags::InstallinatorDocument)
        .unwrap();
    let doc_json = repo
        .read_artifact(&artifact)
        .await?
        .map_ok(Vec::from)
        .try_concat()
        .await?;
    let doc: InstallinatorDocument = serde_json::from_slice(&doc_json).unwrap();
    for artifact in doc.artifacts {
        assert!(
            hashes.contains(&artifact.hash),
            "converted Installinator document references non-existent hash {}",
            artifact.hash
        );
    }

    // The original Installinator document should be accessible, and may
    // reference either v2 or v1-only artifacts.
    hashes.extend(
        repo.installinator_v1_handles().map(|handle| handle.artifact().hash),
    );
    let handle = repo
        .installinator_v1_handles()
        .find(|handle| {
            handle.artifact().hash == repo.installinator_v1_document().unwrap()
        })
        .unwrap();
    let doc_json =
        handle.stream().await?.map_ok(Vec::from).try_concat().await?;
    let doc: InstallinatorDocument = serde_json::from_slice(&doc_json).unwrap();
    for artifact in doc.artifacts {
        assert!(
            hashes.contains(&artifact.hash),
            "original Installinator document references non-existent hash {}",
            artifact.hash
        );
    }

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
        .unsafe_blindly_trust_repo()
        .v1_compatibility(false)
        .load_zip_path(path, &log)
        .await
        .map_err(|error| error.to_string())
        .unwrap();
}
