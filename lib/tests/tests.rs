// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::convert::Infallible;
use std::io::Write;

use bytes::BufMut;
use bytes::BytesMut;
use chrono::Utc;
use futures_util::TryStreamExt;
use futures_util::stream;
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

#[tokio::test]
async fn compute_archive_sha256() -> Result<(), Error> {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let zip = RepositoryEditor::fake(VERSION)?
        .finish()
        .await?
        .generate_root()
        .sign()
        .await?
        .write_zip(BytesMut::new().writer(), Utc::now())
        .await?
        .into_inner()
        .freeze();
    for should_compute in [false, true] {
        let repo = RepositoryLoader::new()
            .compute_archive_sha256(should_compute)
            .trust_store_behavior(TrustStoreBehavior::UnsafeBlindFaith)
            .load_zip_buffer(zip.clone(), &log)
            .await?;
        assert_eq!(repo.archive_sha256().is_some(), should_compute);

        let mut file = camino_tempfile::tempfile().unwrap();
        file.write_all(&zip).unwrap();
        let repo = RepositoryLoader::new()
            .compute_archive_sha256(should_compute)
            .trust_store_behavior(TrustStoreBehavior::UnsafeBlindFaith)
            .load_zip_file(file, None, &log)
            .await?;
        assert_eq!(repo.archive_sha256().is_some(), should_compute);

        let repo = RepositoryLoader::new()
            .compute_archive_sha256(should_compute)
            .trust_store_behavior(TrustStoreBehavior::UnsafeBlindFaith)
            .load_zip_stream(
                stream::once(async { Ok::<_, Infallible>(zip.clone()) }),
                None,
                &log,
            )
            .await?;
        assert_eq!(repo.archive_sha256().is_some(), should_compute);
    }
    Ok(())
}
