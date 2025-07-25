// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, Utc};
use tough::editor::signed::SignedRole;
use tough::schema::Root;

use crate::{AddArtifact, Key, OmicronRepo, utils::merge_anyhow_list};

use super::ArtifactManifest;

/// Assembles a TUF repo from a list of artifacts.
#[derive(Debug)]
pub struct OmicronRepoAssembler {
    log: slog::Logger,
    manifest: ArtifactManifest,
    build_dir: Option<Utf8PathBuf>,
    keys: Vec<Key>,
    root: Option<SignedRole<Root>>,
    expiry: DateTime<Utc>,
    output_path: Utf8PathBuf,
}

impl OmicronRepoAssembler {
    pub fn new(
        log: &slog::Logger,
        manifest: ArtifactManifest,
        keys: Vec<Key>,
        expiry: DateTime<Utc>,
        output_path: Utf8PathBuf,
    ) -> Self {
        Self {
            log: log.new(slog::o!("component" => "OmicronRepoAssembler")),
            manifest,
            build_dir: None,
            keys,
            root: None,
            expiry,
            output_path,
        }
    }

    pub fn set_build_dir(&mut self, build_dir: Utf8PathBuf) -> &mut Self {
        self.build_dir = Some(build_dir);
        self
    }

    pub fn set_root_role(&mut self, root_role: SignedRole<Root>) -> &mut Self {
        self.root = Some(root_role);
        self
    }

    pub async fn build(&self) -> Result<()> {
        let (build_dir, is_temp) = match &self.build_dir {
            Some(dir) => (dir.clone(), false),
            None => {
                // Create a new temporary directory.
                let dir = camino_tempfile::Builder::new()
                    .prefix("tufaceous")
                    .tempdir()?;
                // This will cause the directory to be preserved -- we're going
                // to clean it up if it's successful.
                let path = dir.keep();
                (path, true)
            }
        };

        slog::info!(self.log, "assembling repository in `{build_dir}`");

        match self.build_impl(&build_dir).await {
            Ok(()) => {
                if is_temp {
                    slog::debug!(self.log, "assembly successful, cleaning up");
                    // Log, but otherwise ignore, errors while cleaning up.
                    if let Err(error) = fs_err::remove_dir_all(&build_dir) {
                        slog::warn!(
                            self.log,
                            "failed to clean up temporary directory {build_dir}: {error}"
                        )
                    }
                }

                slog::info!(
                    self.log,
                    "artifacts assembled and archived to `{}`",
                    self.output_path
                );
                Ok(())
            }
            Err(error) => {
                slog::error!(
                    self.log,
                    "assembly failed, failing build directory preserved: `{build_dir}`"
                );
                Err(error)
            }
        }
    }

    async fn build_impl(&self, build_dir: &Utf8Path) -> Result<()> {
        let root = match &self.root {
            Some(root) => root.clone(),
            None => {
                crate::root::new_root(self.keys.clone(), self.expiry).await?
            }
        };
        let mut repository = OmicronRepo::initialize(
            &self.log,
            build_dir,
            self.manifest.system_version.clone(),
            self.keys.clone(),
            root,
            self.expiry,
        )
        .await?
        .into_editor()
        .await?;

        // Add all the artifacts.
        let mut errors = Vec::new();

        for (kind, entries) in &self.manifest.artifacts {
            for data in entries {
                let new_artifact = AddArtifact::new(
                    (*kind).into(),
                    data.name.clone(),
                    data.version.clone(),
                    data.source.clone(),
                    data.deployment_units.clone(),
                );
                let res =
                    repository.add_artifact(&new_artifact).with_context(|| {
                        format!("error adding artifact with kind `{kind}`")
                    });
                if let Err(err) = res {
                    errors.push(err);
                }
            }
        }

        if !errors.is_empty() {
            return Err(merge_anyhow_list(errors));
        }

        // Write out the repository.
        repository.sign_and_finish(self.keys.clone(), self.expiry).await?;

        // Now reopen the repository to archive it into a zip file.
        let repo2 = OmicronRepo::load_untrusted(&self.log, build_dir)
            .await
            .context("error reopening repository to archive")?;
        repo2
            .archive(&self.output_path)
            .context("error archiving repository")?;

        Ok(())
    }
}
