// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;

use anyhow::Result;
use camino::Utf8PathBuf;
use clap::Parser;
use tough::ExpirationEnforcement;
use tufaceous::RepositoryLoader;
use tufaceous::TrustStoreBehavior;

#[derive(Debug, Parser)]
pub struct Args {
    repo: Utf8PathBuf,
}

impl Args {
    pub async fn run(self) -> Result<()> {
        let repo = RepositoryLoader::new()
            .expiration_enforcement(ExpirationEnforcement::Unsafe)
            .trust_store_behavior(TrustStoreBehavior::UnsafeBlindFaith)
            .load_zip_path(self.repo.clone(), &crate::LOG)
            .await?;
        let target_names = repo.targets().keys().collect::<BTreeSet<_>>();
        for target_name in target_names {
            println!("{}", target_name.raw());
        }
        Ok(())
    }
}
