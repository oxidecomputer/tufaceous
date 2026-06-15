// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use camino::Utf8PathBuf;
use clap::Args;
use tough::key_source::LocalKeySource;
use tufaceous::edit::SignedRepository;
use tufaceous::edit::UnsignedRepository;
use tufaceous::error::Error;
use tufaceous::error::ErrorKind;

#[derive(Debug, Args)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SignOptions {
    /// Refuse to generate a signing root
    #[clap(long)]
    no_generate_root: bool,

    /// Path to the signing root [default: generate a root]
    #[clap(long, required_if_eq("no_generate_root", "true"))]
    signing_root: Option<Utf8PathBuf>,

    /// Private signing key listed in the signing root
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
        if let Some(path) = self.signing_root {
            let root = match tokio::fs::read(&path).await {
                Ok(root) => root,
                Err(source) => {
                    return Err(Error::from(ErrorKind::ReadFile {
                        source,
                        path: Some(path),
                    })
                    .into());
                }
            };
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

    #[derive(Parser)]
    struct Args {
        #[clap(flatten)]
        inner: SignOptions,
    }

    #[test]
    fn test_flags() {
        assert_eq!(
            Args::try_parse_from([""]).unwrap().inner,
            SignOptions {
                no_generate_root: false,
                signing_root: None,
                key: vec![]
            }
        );
        assert!(Args::try_parse_from(["", "--no-generate-root"]).is_err());
        let mut args = vec!["", "--signing-root", "root.json"];
        assert_eq!(
            Args::try_parse_from(&args).unwrap().inner,
            SignOptions {
                no_generate_root: false,
                signing_root: Some("root.json".into()),
                key: vec![],
            }
        );
        args.extend(["--key", "key.pem"]);
        assert_eq!(
            Args::try_parse_from(&args).unwrap().inner,
            SignOptions {
                no_generate_root: false,
                signing_root: Some("root.json".into()),
                key: vec!["key.pem".into()],
            }
        );
        args.extend(["--key", "key2.pem"]);
        assert_eq!(
            Args::try_parse_from(&args).unwrap().inner,
            SignOptions {
                no_generate_root: false,
                signing_root: Some("root.json".into()),
                key: vec!["key.pem".into(), "key2.pem".into()],
            }
        );
    }
}
