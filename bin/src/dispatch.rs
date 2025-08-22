// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result, bail};
use camino::Utf8PathBuf;
use chrono::{DateTime, Utc};
use clap::Parser;
use tufaceous_artifact::{ArtifactsDocument, KnownArtifactKind};
use tufaceous_lib::assemble::{ArtifactManifest, OmicronRepoAssembler};
use tufaceous_lib::{ArchiveExtractor, Key, OmicronRepo};

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(subcommand)]
    command: Command,

    #[clap(
        short = 'k',
        long = "key",
        env = "TUFACEOUS_KEY",
        required = false,
        global = true
    )]
    keys: Vec<Key>,

    #[clap(long, value_parser = crate::date::parse_duration_or_datetime, default_value = "7d", global = true)]
    expiry: DateTime<Utc>,

    /// TUF repository path (default: current working directory)
    #[clap(short = 'r', long, global = true)]
    repo: Option<Utf8PathBuf>,
}

impl Args {
    /// Executes these arguments.
    pub async fn exec(self, log: &slog::Logger) -> Result<()> {
        match self.command {
            Command::Assemble {
                manifest_path,
                output_path,
                build_dir,
                no_generate_key,
                skip_all_present,
                allow_non_semver,
                no_installinator_document,
            } => {
                // The filename must end with "zip".
                if output_path.extension() != Some("zip") {
                    bail!("output path `{output_path}` must end with .zip");
                }

                let manifest = ArtifactManifest::from_path(&manifest_path)
                    .context("error reading manifest")?;
                if !allow_non_semver {
                    manifest.verify_all_semver()?;
                }
                if !skip_all_present {
                    manifest.verify_all_present()?;
                }

                let keys = maybe_generate_keys(self.keys, no_generate_key)?;
                let mut assembler = OmicronRepoAssembler::new(
                    log,
                    manifest,
                    keys,
                    self.expiry,
                    !no_installinator_document,
                    output_path,
                );
                if let Some(dir) = build_dir {
                    assembler.set_build_dir(dir);
                }

                assembler.build().await?;

                Ok(())
            }
            Command::Extract {
                archive_file,
                dest,
                no_installinator_document,
            } => {
                let mut extractor = ArchiveExtractor::from_path(&archive_file)?;
                extractor.extract(&dest)?;

                // Now load the repository and ensure it's valid.
                let repo = OmicronRepo::load_untrusted(log, &dest)
                    .await
                    .with_context(|| {
                        format!(
                            "error loading extracted repository at `{dest}` \
                             (extracted files are still available)"
                        )
                    })?;
                let artifacts =
                    repo.read_artifacts().await.with_context(|| {
                        format!(
                            "error loading {} from extracted archive \
                             at `{dest}`",
                            ArtifactsDocument::FILE_NAME
                        )
                    })?;
                if !no_installinator_document {
                    // There should be a reference to an installinator document
                    // within artifacts_document.
                    let installinator_doc_artifact = artifacts
                        .artifacts
                        .iter()
                        .find(|artifact| {
                            artifact.kind.to_known()
                                == Some(
                                    KnownArtifactKind::InstallinatorDocument,
                                )
                        })
                        .context(
                            "could not find artifact with kind \
                            `installinator_document` within artifacts.json",
                        )?;

                    repo.read_installinator_document(
                        &installinator_doc_artifact.target,
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "error loading {} from extracted archive \
                            at `{dest}`",
                            installinator_doc_artifact.target,
                        )
                    })?;
                }

                Ok(())
            }
        }
    }
}

#[derive(Debug, Parser)]
enum Command {
    /// Assembles a repository from a provided manifest.
    Assemble {
        /// Path to artifact manifest.
        manifest_path: Utf8PathBuf,

        /// The path to write the archive to (must end with .zip).
        output_path: Utf8PathBuf,

        /// Directory to use for building artifacts [default: temporary directory]
        #[clap(long)]
        build_dir: Option<Utf8PathBuf>,

        /// Disable random key generation and exit if no keys are provided
        #[clap(long)]
        no_generate_key: bool,

        /// Skip checking to ensure all expected artifacts are present.
        #[clap(long)]
        skip_all_present: bool,

        /// Allow versions to be non-semver.
        ///
        /// Transitional option for v13 -> v14. After v14, versions will be
        /// allowed to be non-semver by default.
        #[clap(long)]
        allow_non_semver: bool,

        /// Do not include the installinator document.
        ///
        /// Transitional option for v15 -> v16, meant to be used for testing.
        #[clap(long)]
        no_installinator_document: bool,
    },
    /// Validates and extracts a repository created by the `assemble` command.
    Extract {
        /// The file to extract.
        archive_file: Utf8PathBuf,

        /// The destination to extract the file to.
        dest: Utf8PathBuf,

        /// Indicate that the file does not contain an installinator document.
        #[clap(long)]
        no_installinator_document: bool,
    },
}

fn maybe_generate_keys(
    keys: Vec<Key>,
    no_generate_key: bool,
) -> Result<Vec<Key>> {
    Ok(if !no_generate_key && keys.is_empty() {
        let key = Key::generate_ed25519()?;
        crate::hint::generated_key(&key);
        vec![key]
    } else {
        keys
    })
}
