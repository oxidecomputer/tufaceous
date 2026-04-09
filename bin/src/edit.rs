// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use camino::Utf8PathBuf;
use chrono::Utc;
use clap::Parser;
use semver::Version;
use tufaceous::ExpirationEnforcement;
use tufaceous::RepositoryLoader;
use tufaceous::TrustStoreBehavior;
use tufaceous::edit::RepositoryEditor;
use tufaceous_artifact::KnownArtifactTags;

use crate::sign::SignOptions;

#[derive(Debug, Parser)]
pub struct Args {
    #[arg(short = 'a', long, num_args(1..))]
    add_artifacts: Vec<Utf8PathBuf>,
    #[clap(long)]
    no_installinator_document: bool,
    #[clap(short = 'o', long)]
    output: Option<Utf8PathBuf>,
    #[arg(short = 'd', long, num_args(1..))]
    remove_targets: Vec<String>,
    repo: Utf8PathBuf,
    #[clap(flatten)]
    sign_options: SignOptions,
    #[clap(short = 'V', long)]
    version: Option<Version>,
}

impl Args {
    pub async fn run(self) -> Result<()> {
        let repo = RepositoryLoader::new()
            .expiration_enforcement(ExpirationEnforcement::Unsafe)
            .trust_store_behavior(TrustStoreBehavior::UnsafeBlindFaith)
            .load_zip_path(self.repo.clone(), &crate::LOG)
            .await?;
        let mut editor = RepositoryEditor::from_repo(&repo)?
            .generate_installinator_document(!self.no_installinator_document);

        // always remove an existing installinator document
        for artifact in
            repo.artifacts().get_all(&KnownArtifactTags::InstallinatorDocument)
        {
            editor = editor.remove_target(&artifact.target_name);
        }

        if let Some(version) = self.version {
            editor = editor.system_version(version);
        }
        for target_name in &self.remove_targets {
            editor = editor.remove_target(target_name);
        }
        for path in self.add_artifacts {
            editor = editor.guess_artifact(path).await?;
        }

        let unsigned = editor.finish().await?;
        let output = self.output.unwrap_or(self.repo);
        self.sign_options
            .sign(unsigned)
            .await?
            .write_zip_file(output, Utc::now())
            .await?;
        Ok(())
    }
}
