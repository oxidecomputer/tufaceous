// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::io::Write;
use std::sync::Arc;

use bytes::BufMut;
use bytes::BytesMut;
use chrono::Utc;
use futures_util::TryStreamExt;
use futures_util::stream;
use semver::Version;
use tufaceous::RepositoryLoader;
use tufaceous::edit::RepositoryEditor;
use tufaceous::error::Error;
use tufaceous_artifact::Artifact;
use tufaceous_artifact::ArtifactHash;
use tufaceous_artifact::KnownArtifactTags;

const V1: Version = Version::new(1, 0, 0);
const V2: Version = Version::new(2, 0, 0);

#[tokio::test]
async fn it_works() -> Result<(), Error> {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let signed = RepositoryEditor::fake(V1)?
        .finish()
        .await?
        .generate_root()
        .sign()
        .await?;
    let zip = signed.write_zip(Vec::new(), Utc::now()).await?;
    let repo = RepositoryLoader::new()
        .trust_root(signed.root())
        .load_zip_buffer(zip, &log)
        .await?;
    for artifact in repo.artifacts() {
        repo.read_artifact(artifact)
            .await?
            .map_ok(|bytes| bytes.to_vec())
            .try_concat()
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn verify_targets() -> Result<(), Error> {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let signed = RepositoryEditor::fake(V1)?
        .finish()
        .await?
        .generate_root()
        .sign()
        .await?;
    let mut zip = signed.write_zip(Vec::new(), Utc::now()).await?;
    let repo = RepositoryLoader::new()
        .trust_root(signed.root())
        .load_zip_buffer(zip.clone(), &log)
        .await?;
    let repo = Arc::new(repo);
    let parallelism = std::thread::available_parallelism().unwrap().get();
    repo.verify_targets(parallelism).await?;

    // Now intentionally fuck up the archive, and ensure verification fails.
    let pos = memchr::memmem::find(&zip, b"hubris")
        .expect("b\"hubris\" not found in archive");
    zip[pos] = b'H'; // flip! that! bit!
    let repo = RepositoryLoader::new()
        .trust_root(signed.root())
        .load_zip_buffer(zip.clone(), &log)
        .await?;
    let repo = Arc::new(repo);
    let err = repo.verify_targets(parallelism).await.unwrap_err();
    // This error ultimately comes from `rawzip`'s CRC-32 checking.
    assert!(err.to_string().contains("Invalid checksum"));

    Ok(())
}

#[tokio::test]
async fn no_artifacts() -> Result<(), Error> {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let signed = RepositoryEditor::new(V1)?
        .set_generate_installinator_document(false)
        .finish()
        .await?
        .generate_root()
        .sign()
        .await?;
    let zip = signed.write_zip(Vec::new(), Utc::now()).await?;
    let repo = RepositoryLoader::new()
        .trust_root(signed.root())
        .load_zip_buffer(zip, &log)
        .await?;
    assert_eq!(repo.artifacts().len(), 0);
    assert!(repo.artifacts().is_empty());
    Ok(())
}

#[tokio::test]
async fn fake_artifacts_are_distinct() -> Result<(), Error> {
    let log = slog::Logger::root(slog::Discard, slog::o!());

    let signed = RepositoryEditor::fake(V1)?
        .finish()
        .await?
        .generate_root()
        .sign()
        .await?;
    let zip = signed.write_zip(Vec::new(), Utc::now()).await?;
    let repo1 = RepositoryLoader::new()
        .trust_root(signed.root())
        .load_zip_buffer(zip, &log)
        .await?;

    let signed = RepositoryEditor::fake(V2)?
        .finish()
        .await?
        .generate_root()
        .sign()
        .await?;
    let zip = signed.write_zip(Vec::new(), Utc::now()).await?;
    let repo2 = RepositoryLoader::new()
        .trust_root(signed.root())
        .load_zip_buffer(zip, &log)
        .await?;

    let hashes1 = repo1
        .artifacts()
        .iter()
        .map(|artifact| artifact.hash)
        .collect::<BTreeSet<_>>();
    let hashes2 = repo2
        .artifacts()
        .iter()
        .map(|artifact| artifact.hash)
        .collect::<BTreeSet<_>>();
    if !hashes1.is_disjoint(&hashes2) {
        let intersection =
            hashes1.intersection(&hashes2).collect::<BTreeSet<_>>();
        let mut artifacts = BTreeMap::<ArtifactHash, Vec<&Artifact>>::new();
        for repo in [&repo1, &repo2] {
            for artifact in repo.artifacts() {
                if intersection.contains(&artifact.hash) {
                    artifacts.entry(artifact.hash).or_default().push(artifact);
                }
            }
        }
        panic!(
            "artifacts from fake repos of different versions \
            have the same hash: {:?}",
            artifacts.values()
        );
    }

    Ok(())
}

#[tokio::test]
async fn inconsistent_fake() -> Result<(), Error> {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let signed = RepositoryEditor::fake(V1)?
        .finish()
        .await?
        .generate_root()
        .sign()
        .await?;
    let zip = signed.write_zip(Vec::new(), Utc::now()).await?;
    let repo1 = RepositoryLoader::new()
        .trust_root(signed.root())
        .load_zip_buffer(zip, &log)
        .await?;

    let artifact_v1 = V1.to_string().parse()?;
    let artifact_v2 = V2.to_string().parse()?;
    let signed =
        RepositoryEditor::inconsistent_fake(V2, &artifact_v2, &artifact_v1)?
            .finish()
            .await?
            .generate_root()
            .sign()
            .await?;
    let zip = signed.write_zip(Vec::new(), Utc::now()).await?;
    let repo2 = RepositoryLoader::new()
        .trust_root(signed.root())
        .load_zip_buffer(zip, &log)
        .await?;

    for (first, second) in
        repo1.artifacts().iter().zip(repo2.artifacts().iter())
    {
        // Each artifact should have the same tags.
        assert_eq!(first.tags, second.tags);
        // If this is the Installinator document, skip the rest of the checks.
        // The Installinator document's version is always the system version.
        if first.known_tags() == Some(KnownArtifactTags::InstallinatorDocument)
        {
            continue;
        }
        // The first artifact should be 1.0.0, and the second should be 2.0.0.
        assert_eq!(first.version, artifact_v1);
        assert_eq!(second.version, artifact_v2);
        // The artifacts should have the same contents (hash and length), as they
        // should both have an interior version of 1.0.0.
        assert_eq!(first.hash, second.hash);
        assert_eq!(first.length, second.length);
    }

    Ok(())
}

#[tokio::test]
async fn compute_archive_sha256() -> Result<(), Error> {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let signed = RepositoryEditor::fake(V1)?
        .finish()
        .await?
        .generate_root()
        .sign()
        .await?;
    let zip = signed
        .write_zip(BytesMut::new().writer(), Utc::now())
        .await?
        .into_inner()
        .freeze();
    for should_compute in [false, true] {
        let repo = RepositoryLoader::new()
            .compute_archive_sha256(should_compute)
            .trust_root(signed.root())
            .load_zip_buffer(zip.clone(), &log)
            .await?;
        assert_eq!(repo.archive_sha256().is_some(), should_compute);

        let mut file = camino_tempfile::tempfile().unwrap();
        file.write_all(&zip).unwrap();
        let repo = RepositoryLoader::new()
            .compute_archive_sha256(should_compute)
            .trust_root(signed.root())
            .load_zip_file(file, None, &log)
            .await?;
        assert_eq!(repo.archive_sha256().is_some(), should_compute);

        let repo = RepositoryLoader::new()
            .compute_archive_sha256(should_compute)
            .trust_root(signed.root())
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
