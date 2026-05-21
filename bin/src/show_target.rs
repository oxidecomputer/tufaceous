// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::io::Write;

use anyhow::Context;
use anyhow::Result;
use camino::Utf8PathBuf;
use clap::Parser;
use futures_util::TryStreamExt;
use tufaceous::ExpirationEnforcement;
use tufaceous::RepositoryLoader;
use tufaceous::TrustStoreBehavior;

#[derive(Debug, Parser)]
pub struct Args {
    repo: Utf8PathBuf,
    target_name: String,
}

impl Args {
    pub async fn run(self) -> Result<()> {
        let repo = RepositoryLoader::new()
            // TODO after v2 merge: Create a LoadOptions struct for configuring
            // expiration enforcement and trust store behavior.
            .expiration_enforcement(ExpirationEnforcement::Unsafe)
            .trust_store_behavior(TrustStoreBehavior::UnsafeBlindFaith)
            .load_zip_path(self.repo.clone(), &crate::LOG)
            .await?;
        let mut stream = repo.read_target(&self.target_name).await?;
        let mut stdout = std::io::stdout().lock();
        while let Some(bytes) = stream.try_next().await? {
            stdout.write_all(&bytes).context("failed to write to stdout")?;
        }
        Ok(())
    }
}
