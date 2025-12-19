// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::Utc;
use futures_util::TryStreamExt;
use semver::Version;
use tufaceous::RepositoryLoader;
use tufaceous::TrustStoreBehavior;
use tufaceous::edit::RepositoryEditor;
use tufaceous::error::Error;

const VERSION: Version = Version::new(1, 0, 0);

#[tokio::test]
async fn it_works() -> Result<(), Error> {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let zip = RepositoryEditor::fake(VERSION)?
        .finish()
        .await?
        .generate_root()
        .sign()
        .await?
        .write_zip(Vec::new(), Utc::now())
        .await?;
    let repo = RepositoryLoader::new()
        .trust_store_behavior(TrustStoreBehavior::UnsafeBlindFaith)
        .load_zip_buffer(zip, &log)
        .await?;
    for artifact in repo.artifacts() {
        repo.read_target(&artifact.target_name)
            .await?
            .map_ok(|bytes| bytes.to_vec())
            .try_concat()
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn no_artifacts() -> Result<(), Error> {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let zip = RepositoryEditor::new(VERSION)
        .generate_installinator_document(false)
        .finish()
        .await?
        .generate_root()
        .sign()
        .await?
        .write_zip(Vec::new(), Utc::now())
        .await?;
    let repo = RepositoryLoader::new()
        .trust_store_behavior(TrustStoreBehavior::UnsafeBlindFaith)
        .load_zip_buffer(zip, &log)
        .await?;
    assert_eq!(repo.artifacts().len(), 0);
    assert!(repo.artifacts().is_empty());
    Ok(())
}

#[tokio::test]
async fn empty_artifact() -> Result<(), Error> {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let zip = RepositoryEditor::new(VERSION)
        .generate_installinator_document(false)
        .fake_artifact(
            "empty.img".to_owned(),
            "1.0.0".parse().unwrap(),
            tufaceous_artifact::KnownArtifactTags::InstallinatorDocument {},
            0,
        )
        .finish()
        .await?
        .generate_root()
        .sign()
        .await?
        .write_zip(Vec::new(), Utc::now())
        .await?;
    let repo = RepositoryLoader::new()
        .trust_store_behavior(TrustStoreBehavior::UnsafeBlindFaith)
        .load_zip_buffer(zip, &log)
        .await?;
    let artifacts = repo.artifacts().iter().collect::<Vec<_>>();
    assert_eq!(artifacts.len(), 1);
    let data = repo
        .read_target(&artifacts[0].target_name)
        .await?
        .map_ok(|bytes| bytes.to_vec())
        .try_concat()
        .await?;
    assert!(data.is_empty());
    Ok(())
}
