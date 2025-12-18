// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Context;
use anyhow::Result;
use camino::Utf8Path;
use camino::Utf8PathBuf;
use chrono::Utc;
use clap::Parser;
use semver::Version;
use tufaceous::edit::RepositoryEditor;
use tufaceous_artifact::ArtifactVersion;
use tufaceous_artifact::KnownArtifactTags;
use tufaceous_artifact::OsVariant;
use tufaceous_artifact::RotSlot;

use crate::sign::SignOptions;

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(long)]
    version: Version,
    #[clap(long)]
    no_installinator_document: bool,
    #[clap(long)]
    measurement_corpus: Vec<Utf8PathBuf>,
    #[clap(long)]
    host_os_dir: Option<Utf8PathBuf>,
    #[clap(long)]
    recovery_os_dir: Option<Utf8PathBuf>,
    #[clap(long)]
    rot_slot_a: Vec<Utf8PathBuf>,
    #[clap(long)]
    rot_slot_b: Vec<Utf8PathBuf>,
    #[clap(long)]
    rot_bootloader: Vec<Utf8PathBuf>,
    #[clap(long)]
    sp: Vec<Utf8PathBuf>,
    #[clap(long)]
    zone: Vec<Utf8PathBuf>,

    #[clap(flatten)]
    sign_options: SignOptions,
    output: Utf8PathBuf,
}

impl Args {
    pub async fn run(self) -> Result<()> {
        let version = ArtifactVersion::new(self.version.to_string())?;
        let mut editor = RepositoryEditor::new(self.version);
        if !self.no_installinator_document {
            editor = editor.generate_installinator_document();
        }
        for path in self.measurement_corpus {
            editor = editor
                .add_artifact(
                    file_name(&path)?,
                    version.clone(),
                    KnownArtifactTags::MeasurementCorpus {},
                    path,
                )
                .await?;
        }
        if let Some(path) = self.host_os_dir {
            editor = editor.add_os_artifacts(OsVariant::Host, path).await?;
        }
        if let Some(path) = self.recovery_os_dir {
            editor = editor.add_os_artifacts(OsVariant::Recovery, path).await?;
        }
        for (slot, paths) in
            [(RotSlot::A, self.rot_slot_a), (RotSlot::B, self.rot_slot_b)]
        {
            for path in paths {
                editor =
                    editor.add_rot_image(file_name(&path)?, slot, path).await?;
            }
        }
        for path in self.rot_bootloader {
            editor = editor
                .add_rot_bootloader_image(file_name(&path)?, path)
                .await?;
        }
        for path in self.sp {
            editor = editor.add_sp_image(file_name(&path)?, path).await?;
        }
        for path in self.zone {
            editor = editor.add_zone_image(&file_name(&path)?, path).await?;
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

fn file_name(path: &Utf8Path) -> Result<String> {
    path.file_name()
        .map(str::to_owned)
        .with_context(|| format!("{path} has no file name"))
}
