// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::io::Write;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use futures_util::TryStreamExt;

use crate::load::LoadOptions;

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(flatten)]
    load_options: LoadOptions,
    /// Targets to output
    ///
    /// This is the path under "repo/targets/" in a ZIP archive. The
    /// list-targets command lists the target names.
    target_name: String,
}

impl Args {
    pub async fn run(self) -> Result<()> {
        let repo = self.load_options.load().await?;
        let mut stream = repo.read_target(&self.target_name).await?;
        let mut stdout = std::io::stdout().lock();
        while let Some(bytes) = stream.try_next().await? {
            stdout.write_all(&bytes).context("failed to write to stdout")?;
        }
        Ok(())
    }
}
