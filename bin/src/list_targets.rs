// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;

use anyhow::Result;
use camino::Utf8PathBuf;
use clap::Parser;

use crate::load::LoadOptions;

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(flatten)]
    load_options: LoadOptions,
    repo: Utf8PathBuf,
}

impl Args {
    pub async fn run(self) -> Result<()> {
        let repo = self
            .load_options
            .loader()
            .await?
            .load_zip_path(self.repo.clone(), &crate::LOG)
            .await?;
        let target_names = repo.targets().keys().collect::<BTreeSet<_>>();
        for target_name in target_names {
            println!("{}", target_name.raw());
        }
        Ok(())
    }
}
