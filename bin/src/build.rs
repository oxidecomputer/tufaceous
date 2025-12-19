// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use camino::Utf8PathBuf;
use chrono::Utc;
use clap::Parser;
use semver::Version;
use tufaceous::edit::RepositoryEditor;

use crate::sign::SignOptions;

#[derive(Debug, Parser)]
pub struct Args {
    artifacts: Vec<Utf8PathBuf>,
    #[clap(long)]
    no_installinator_document: bool,
    #[clap(short = 'o', long)]
    output: Utf8PathBuf,
    #[clap(flatten)]
    sign_options: SignOptions,
    #[clap(short = 'V', long)]
    version: Version,
}

impl Args {
    pub async fn run(self) -> Result<()> {
        let mut editor = RepositoryEditor::new(self.version)
            .generate_installinator_document(!self.no_installinator_document);
        for path in self.artifacts {
            editor = editor.guess_artifact(path).await?;
        }
        let unsigned = editor.finish().await?;
        self.sign_options
            .sign(unsigned)
            .await?
            .write_zip_file(self.output, Utc::now())
            .await?;
        Ok(())
    }
}
