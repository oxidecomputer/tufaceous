// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::Utc;
use semver::Version;
use tufaceous::CheckProblem;
use tufaceous::Repository;
use tufaceous::RepositoryLoader;
use tufaceous::TrustStoreBehavior;
use tufaceous::edit::RepositoryEditor;
use tufaceous::error::Error;
use tufaceous_artifact::KnownArtifactTags;

const V1: Version = Version::new(1, 0, 0);

#[tokio::test]
async fn fake_checks_out() -> Result<(), Error> {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let repo = Repository::fake(V1, &log).await?;
    let problems = repo.check_problems().await;
    assert!(problems.is_empty(), "repo has unexpected problems: {problems:?}");
    Ok(())
}

#[tokio::test]
async fn missing_installinator() -> Result<(), Error> {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let zip = RepositoryEditor::fake(V1)?
        .set_generate_installinator_document(false)
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
    let problems = repo.check_problems().await;
    assert!(
        matches!(
            problems.as_slice(),
            [CheckProblem::MissingArtifact(
                KnownArtifactTags::InstallinatorDocument
            )]
        ),
        "repo has unexpected problems: {problems:?}"
    );
    Ok(())
}
