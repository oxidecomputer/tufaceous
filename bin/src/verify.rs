// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::error::Error;
use std::fmt::Display;

use anyhow::Result;
use anyhow::ensure;
use clap::Parser;
use tufaceous::CheckProblem;
use tufaceous::RepositoryLoader;
use tufaceous_artifact::ArtifactHash;

use crate::load::LoadOptions;

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(flatten)]
    load_options: LoadOptions,
    /// Number of threads to use while verifying targets
    #[clap(short = 'j', alias = "jobs", default_value_t = default_threads())]
    threads: usize,
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(1)
}

impl Args {
    pub async fn run(self) -> Result<()> {
        let repo_path = self.load_options.repo.clone();
        let repo = self
            .load_options
            .with_loader(
                RepositoryLoader::new()
                    .compute_archive_sha256(true)
                    .v1_compatibility(true),
            )
            .await?;
        let sha256 = ArtifactHash(
            *repo.archive_sha256().expect("repo hash should be calculated"),
        );

        repo.verify_targets(self.threads).await?;

        let problems = repo.check_problems().await?;
        ensure!(
            problems.is_empty(),
            "found compatibility problems:\n{}",
            WriteProblems(&problems)
        );

        eprintln!("{repo_path}: OK, SHA256 = {sha256}");
        Ok(())
    }
}

struct WriteProblems<'a>(&'a [CheckProblem]);

impl Display for WriteProblems<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut nl = "";
        for problem in self.0 {
            write!(f, "{nl}- {problem}")?;
            let mut source = problem.source();
            while let Some(s) = source {
                write!(f, ": {s}")?;
                source = s.source();
            }
            nl = "\n";
        }
        Ok(())
    }
}
