// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use camino::Utf8PathBuf;
use clap::Args;
use clap::builder::ArgPredicate;
use tufaceous::ExpirationEnforcement;
use tufaceous::Repository;
use tufaceous::RepositoryLoader;
use tufaceous::error::Error;
use tufaceous::error::ErrorKind;

#[derive(Debug, Args)]
#[cfg_attr(test, derive(PartialEq))]
pub struct LoadOptions {
    /// Allow loading a repository with an expired signature.
    #[clap(
        long,
        default_value_if("force_load", ArgPredicate::IsPresent, "true")
    )]
    allow_expired: bool,

    /// Blindly trust whatever root is contained in the repository
    ///
    /// This reads the trust root by fetching metadata/1.root.json from the
    /// repository, then proceeds with normal verification. The repository must
    /// be validly signed, but with this set we do not care who signed it.
    #[clap(
        long,
        default_value_if("force_load", ArgPredicate::IsPresent, "true")
    )]
    blindly_trust: bool,

    /// Shorthand for --allow-expired --blindly-trust.
    #[clap(short('f'), long)]
    force_load: bool,

    /// Trust roots to verify the repository
    ///
    /// This flag is required unless --blindly-trust or --force-load is set.
    #[clap(
        short('r'),
        long("trust-roots"),
        conflicts_with("blindly_trust"),
        required_unless_present_any(["blindly_trust", "force_load"])
    )]
    trust_roots: Vec<Utf8PathBuf>,

    /// Input repository path
    pub repo: Utf8PathBuf,
}

impl LoadOptions {
    pub async fn load(self) -> Result<Repository, Error> {
        self.with_loader(RepositoryLoader::new()).await
    }

    pub async fn with_loader(
        self,
        mut loader: RepositoryLoader,
    ) -> Result<Repository, Error> {
        for trust_root in self.trust_roots {
            let root =
                tokio::fs::read(&trust_root).await.map_err(|source| {
                    ErrorKind::ReadFile { source, path: Some(trust_root) }
                })?;
            loader = loader.trust_root(root);
        }
        if self.allow_expired {
            loader =
                loader.expiration_enforcement(ExpirationEnforcement::Unsafe);
        }
        if self.blindly_trust {
            loader = loader.unsafe_blindly_trust_repo();
        }
        loader.load_zip_path(self.repo, &crate::LOG).await
    }
}

#[cfg(test)]
mod tests {
    use camino::Utf8PathBuf;
    use clap::Parser;

    use crate::load::LoadOptions;

    #[derive(Debug, Parser)]
    struct Args {
        #[clap(flatten)]
        inner: LoadOptions,
    }

    #[test]
    fn test_force_load() {
        assert_eq!(
            Args::try_parse_from(["", "-f", "repo.zip"]).unwrap().inner,
            LoadOptions {
                allow_expired: true,
                blindly_trust: true,
                force_load: true,
                trust_roots: vec![],
                repo: Utf8PathBuf::from("repo.zip"),
            }
        );
        // ... but they default to false if --force-load is not used:
        assert_eq!(
            Args::try_parse_from(["", "-r", "/dev/null", "repo.zip"])
                .unwrap()
                .inner,
            LoadOptions {
                allow_expired: false,
                blindly_trust: false,
                force_load: false,
                trust_roots: vec!["/dev/null".into()],
                repo: Utf8PathBuf::from("repo.zip"),
            }
        );
        // --force-load doesn't conflict with --trust-roots
        assert_eq!(
            Args::try_parse_from(["", "-f", "-r", "/dev/null", "repo.zip"])
                .unwrap()
                .inner,
            LoadOptions {
                allow_expired: true,
                blindly_trust: true,
                force_load: true,
                trust_roots: vec!["/dev/null".into()],
                repo: Utf8PathBuf::from("repo.zip"),
            }
        );
    }

    #[test]
    fn test_trust_roots_required() {
        let error =
            Args::try_parse_from(["", "repo.zip"]).unwrap_err().to_string();
        assert!(
            error.contains(
                "the following required arguments were not provided:"
            )
        );
        assert!(error.contains("--trust-roots <TRUST_ROOTS>"));

        // ... but not if --blindly-trust or --force-load is set!
        Args::try_parse_from(["", "--blindly-trust", "repo.zip"]).unwrap();
        Args::try_parse_from(["", "--force-load", "repo.zip"]).unwrap();
    }

    #[test]
    fn test_trust_roots_conflicts() {
        let error = Args::try_parse_from([
            "",
            "--trust-roots",
            "/dev/null",
            "--blindly-trust",
            "repo.zip",
        ])
        .unwrap_err()
        .to_string();
        assert!(error.contains(
            "the argument '--trust-roots <TRUST_ROOTS>' \
            cannot be used with '--blindly-trust'"
        ));
    }
}
