// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::HashMap;
use std::io::Write;

use anyhow::Result;
use camino::Utf8PathBuf;
use camino_tempfile::NamedUtf8TempFile;
use sha2::{Digest, Sha256};
use tough::editor::RepositoryEditor;
use tough::schema::{Hashes, Target};
use tufaceous_artifact::ArtifactHash;

pub(crate) struct TargetWriter {
    file: NamedUtf8TempFile,
    targets_dir: Utf8PathBuf,
    name: String,
    length: u64,
    hasher: Sha256,
}

impl TargetWriter {
    pub(crate) fn new(
        targets_dir: impl Into<Utf8PathBuf>,
        name: impl Into<String>,
    ) -> Result<TargetWriter> {
        let targets_dir = targets_dir.into();
        Ok(TargetWriter {
            file: NamedUtf8TempFile::new_in(&targets_dir)?,
            targets_dir,
            name: name.into(),
            length: 0,
            hasher: Sha256::default(),
        })
    }

    /// Marks that writing has been completed, though the file is still
    /// temporary and not persisted yet.
    ///
    /// The main goal is to provide a way to obtain the hash of the file without
    /// persisting it.
    pub(crate) fn finish_write(self) -> TargetFinishWrite {
        let digest = self.hasher.finalize();
        TargetFinishWrite {
            file: self.file,
            targets_dir: self.targets_dir,
            name: self.name,
            length: self.length,
            digest: ArtifactHash(digest.into()),
        }
    }
}

#[must_use = "the file is still temporary and must be finalized"]
pub(crate) struct TargetFinishWrite {
    file: NamedUtf8TempFile,
    targets_dir: Utf8PathBuf,
    name: String,
    length: u64,
    digest: ArtifactHash,
}

impl TargetFinishWrite {
    pub(crate) fn digest(&self) -> ArtifactHash {
        self.digest
    }

    pub(crate) fn finalize(
        self,
        editor: &mut RepositoryEditor,
    ) -> Result<ArtifactHash> {
        self.file.persist(self.targets_dir.join(format!(
            "{}.{}",
            hex::encode(self.digest.0),
            self.name
        )))?;
        editor.add_target(
            self.name,
            Target {
                length: self.length,
                hashes: Hashes {
                    sha256: Vec::from(self.digest.0).into(),
                    _extra: HashMap::new(),
                },
                custom: HashMap::new(),
                _extra: HashMap::new(),
            },
        )?;
        Ok(self.digest)
    }
}

impl Write for TargetWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.file.write(buf)?;
        self.length += u64::try_from(n).unwrap();
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
