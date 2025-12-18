// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use camino::Utf8PathBuf;
use clap::Parser;
use fs_err::tokio as fs;
use tough::key_source::LocalKeySource;
use tufaceous::edit::SignedRepository;
use tufaceous::edit::UnsignedRepository;

#[derive(Debug, Parser)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SignOptions {
    #[clap(long)]
    no_generate_root: bool,
    #[clap(long, required_if_eq("no_generate_root", "true"))]
    root: Option<Utf8PathBuf>,
    #[clap(long)]
    key: Vec<Utf8PathBuf>,
}

impl SignOptions {
    pub async fn sign(
        self,
        mut unsigned: UnsignedRepository<'_>,
    ) -> Result<SignedRepository<'_>> {
        if !self.no_generate_root {
            unsigned = unsigned.generate_root();
        }
        if let Some(path) = self.root {
            let root = fs::read(path).await?;
            unsigned = unsigned.root(root);
        }
        for path in self.key {
            let source = LocalKeySource { path: path.into() };
            unsigned = unsigned.key(source);
        }
        Ok(unsigned.sign().await?)
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::sign::SignOptions;

    #[test]
    fn test_flags() {
        assert_eq!(
            SignOptions::try_parse_from([""]).unwrap(),
            SignOptions { no_generate_root: false, root: None, key: vec![] }
        );
        assert!(
            SignOptions::try_parse_from(["", "--no-generate-root"]).is_err()
        );
        let mut args = vec!["", "--root", "root.json"];
        assert_eq!(
            SignOptions::try_parse_from(&args).unwrap(),
            SignOptions {
                no_generate_root: false,
                root: Some("root.json".into()),
                key: vec![],
            }
        );
        args.extend(["--key", "key.pem"]);
        assert_eq!(
            SignOptions::try_parse_from(&args).unwrap(),
            SignOptions {
                no_generate_root: false,
                root: Some("root.json".into()),
                key: vec!["key.pem".into()],
            }
        );
        args.extend(["--key", "key2.pem"]);
        assert_eq!(
            SignOptions::try_parse_from(&args).unwrap(),
            SignOptions {
                no_generate_root: false,
                root: Some("root.json".into()),
                key: vec!["key.pem".into(), "key2.pem".into()],
            }
        );
    }
}
