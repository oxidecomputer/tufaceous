// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt::Debug;

use bytes::Bytes;
use camino::Utf8PathBuf;
use futures_util::Stream;
use futures_util::TryStreamExt;
use futures_util::pin_mut;
use sha2::Digest;
use sha2::Sha256;
use slog::Logger;
use tokio::io::AsyncWriteExt;
pub use tough::ExpirationEnforcement;
pub use tough::Limits;
use url::Url;

use crate::Repository;
use crate::ZipTransport;
use crate::error::Error;
use crate::error::ErrorKind;
use crate::error::try_path;

/// Controls how repository trust is established.
///
/// Used in [`RepositoryLoader::trust_store_behavior`].
#[derive(Debug, Clone, Copy, Default)]
pub enum TrustStoreBehavior {
    /// Verification by the provided trust roots is required.
    ///
    /// This is the default behavior.
    #[default]
    Required,
    /// The trust root is established by fetching `metadata/1.root.json` from
    /// the repository. Verification then proceeds normally.
    UnsafeBlindFaith,
}

#[derive(Debug, Clone, Default)]
#[must_use]
pub struct RepositoryLoader {
    compute_archive_sha256: bool,
    expiration_enforcement: ExpirationEnforcement,
    limits: Limits,
    metadata_base_url: Option<Url>,
    targets_base_url: Option<Url>,
    trust_roots: Vec<Vec<u8>>,
    trust_store_behavior: TrustStoreBehavior,
    v1_compatibility: bool,
}

impl RepositoryLoader {
    /// Constructs a new `RepositoryLoader`.
    ///
    /// This is the same as `Repository::loader()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set whether to compute and store the SHA256 digest of the archive, if an
    /// archive is used to load the repository.
    ///
    /// Only affects [`Self::load_zip_buffer`], [`Self::load_zip_path`],
    /// [`Self::load_zip_file`], and [`Self::load_zip_stream`].
    pub fn compute_archive_sha256(self, compute_archive_sha256: bool) -> Self {
        Self { compute_archive_sha256, ..self }
    }

    /// Set whether metadata expiration times are enforced.
    pub fn expiration_enforcement(
        self,
        expiration_enforcement: ExpirationEnforcement,
    ) -> Self {
        Self { expiration_enforcement, ..self }
    }

    /// Set limits used while fetching repository metadata.
    pub fn limits(self, limits: Limits) -> Self {
        Self { limits, ..self }
    }

    /// Set the metadata base URL.
    pub fn metadata_base_url(self, metadata_base_url: Url) -> Self {
        Self { metadata_base_url: Some(metadata_base_url), ..self }
    }

    /// Set the targets base URL.
    pub fn targets_base_url(self, targets_base_url: Url) -> Self {
        Self { targets_base_url: Some(targets_base_url), ..self }
    }

    /// Add a trusted root role to the trust store.
    pub fn trust_root(mut self, trust_root: impl AsRef<[u8]>) -> Self {
        self.trust_roots.push(trust_root.as_ref().into());
        self
    }

    /// Add additional trusted root roles to the trust store.
    pub fn trust_roots(
        mut self,
        trust_roots: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Self {
        let iter = trust_roots.into_iter().map(|root| root.as_ref().into());
        self.trust_roots.extend(iter);
        self
    }

    /// Set how repository trust is established.
    pub fn trust_store_behavior(
        self,
        trust_store_behavior: TrustStoreBehavior,
    ) -> Self {
        Self { trust_store_behavior, ..self }
    }

    /// Enable compatibility with v1-format repositories.
    ///
    /// If a v1-format repository is encountered, composite artifacts are
    /// extracted into temporary files in [`std::env::temp_dir()`]. Artifacts
    /// are not extracted in parallel to avoid unexpectedly using too many
    /// resources. Reading a v1-format repository takes on the order of about 10
    /// seconds on a 2025-era CPU.
    pub fn v1_compatibility(self, v1_compatibility: bool) -> Self {
        Self { v1_compatibility, ..self }
    }

    fn zip_base_urls(self) -> Self {
        self.metadata_base_url(
            "zip:///repo/metadata/"
                .parse()
                .expect("`zip:///repo/metadata/` is a valid URL"),
        )
        .targets_base_url(
            "zip:///repo/targets/"
                .parse()
                .expect("`zip:///repo/targets/` is a valid URL"),
        )
    }

    /// Load a Tufaceous-generated ZIP archive from an owned buffer.
    pub async fn load_zip_buffer<T>(
        self,
        data: T,
        log: &Logger,
    ) -> Result<Repository, Error>
    where
        T: AsRef<[u8]> + Debug + Send + Sync + 'static,
    {
        let (data, sha256) = if self.compute_archive_sha256 {
            tokio::task::spawn_blocking(move || {
                let digest = Sha256::digest(&data).into();
                (data, Some(digest))
            })
            .await?
        } else {
            (data, None)
        };
        let transport = ZipTransport::from_slice(data, log)?;
        let mut repo = self.zip_base_urls().load(transport, log).await?;
        repo.archive_sha256 = sha256;
        Ok(repo)
    }

    /// Load a Tufaceous-generated ZIP archive from a file path.
    pub async fn load_zip_path(
        self,
        archive_path: Utf8PathBuf,
        log: &Logger,
    ) -> Result<Repository, Error> {
        let file = try_path!(
            tokio::fs::File::open(&archive_path).await,
            OpenFile,
            archive_path
        );
        self.load_zip_file(file.into_std().await, Some(archive_path), log).await
    }

    /// Load a Tufaceous-generated ZIP archive from an opened file.
    ///
    /// `archive_path` is used in errors, if available.
    pub async fn load_zip_file(
        self,
        mut file: std::fs::File,
        archive_path: Option<Utf8PathBuf>,
        log: &Logger,
    ) -> Result<Repository, Error> {
        let (file, sha256) = if self.compute_archive_sha256 {
            let path = archive_path.clone();
            tokio::task::spawn_blocking(move || {
                let mut hasher = Sha256::new();
                try_path!(
                    std::io::copy(&mut file, &mut hasher),
                    ReadFile,
                    path
                );
                Ok::<_, Error>((file, Some(hasher.finalize().into())))
            })
            .await??
        } else {
            (file, None)
        };

        let transport =
            ZipTransport::from_file(file, archive_path.clone(), log).await?;
        let mut repo = self.zip_base_urls().load(transport, log).await?;
        repo.archive_path = archive_path;
        repo.archive_sha256 = sha256;
        Ok(repo)
    }

    /// Load a Tufaceous-generated ZIP archive from a stream.
    ///
    /// This writes the contents of the stream to a temporary file. You can
    /// optionally provide a maximum number of bytes that will be written. If
    /// this is not provided, you should ensure something else is limiting the
    /// size of this stream (such as an HTTP body length limit).
    pub async fn load_zip_stream<E>(
        self,
        stream: impl Stream<Item = Result<Bytes, E>>,
        limit: Option<u64>,
        log: &Logger,
    ) -> Result<Repository, Error>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        pin_mut!(stream);
        let file =
            camino_tempfile::tempfile().map_err(ErrorKind::CreateTempFile)?;
        let mut file = tokio::fs::File::from(file);
        let mut hasher = self.compute_archive_sha256.then(Sha256::new);
        let mut bytes_read = limit.map(|_| 0u64);
        while let Some(chunk) = stream
            .try_next()
            .await
            .map_err(|source| ErrorKind::ReadStream(Box::new(source)))?
        {
            if let Some(limit) = limit
                && let Some(bytes_read) = bytes_read.as_mut()
            {
                *bytes_read = u64::try_from(chunk.len())
                    .ok()
                    .and_then(|len| bytes_read.checked_add(len))
                    .ok_or(ErrorKind::StreamLimit { limit })?;
                if *bytes_read > limit {
                    return Err(ErrorKind::StreamLimit { limit }.into());
                }
            }
            if let Some(hasher) = hasher.as_mut() {
                hasher.update(&chunk);
            }
            try_path!(file.write_all(&chunk).await, WriteFile, None);
        }
        let mut repo =
            self.load_zip_file(file.into_std().await, None, log).await?;
        repo.archive_sha256 = hasher.map(|hasher| hasher.finalize().into());
        Ok(repo)
    }

    /// Load a repository from the configured metadata and targets base URLs
    /// using the given transport.
    pub async fn load(
        self,
        transport: impl tough::Transport + Clone + 'static,
        log: &Logger,
    ) -> Result<Repository, Error> {
        let Some(metadata_base_url) = self.metadata_base_url else {
            return Err(ErrorKind::MetadataBaseUrlUnset.into());
        };
        let Some(targets_base_url) = self.targets_base_url else {
            return Err(ErrorKind::TargetsBaseUrlUnset.into());
        };

        let trust_roots = match self.trust_store_behavior {
            TrustStoreBehavior::Required => self.trust_roots,
            TrustStoreBehavior::UnsafeBlindFaith => {
                let root_path = "1.root.json";
                let root_url =
                    metadata_base_url.join(root_path).map_err(|source| {
                        ErrorKind::UrlJoin {
                            source,
                            url: root_path,
                            base: metadata_base_url.to_string(),
                        }
                    })?;
                let mut stream = transport
                    .fetch(root_url.clone())
                    .await
                    .map_err(ErrorKind::Fetch)?;
                let mut root = Vec::new();
                while let Some(bytes) =
                    stream.try_next().await.map_err(ErrorKind::Fetch)?
                {
                    root.extend_from_slice(&bytes);
                }
                vec![root]
            }
        };

        let mut last_error = ErrorKind::NoTrustRoots;
        for trust_root in trust_roots {
            match tough::RepositoryLoader::new(
                &trust_root,
                metadata_base_url.clone(),
                targets_base_url.clone(),
            )
            .expiration_enforcement(self.expiration_enforcement)
            .limits(self.limits)
            .transport(transport.clone())
            .load()
            .await
            {
                Ok(repo) => {
                    return Repository::from_loaded(
                        repo,
                        log,
                        trust_root,
                        None,
                        None,
                        self.v1_compatibility,
                    )
                    .await;
                }
                Err(error) => {
                    if matches!(
                        error,
                        tough::error::Error::VerifyMetadata { .. }
                            | tough::error::Error::VerifyTrustedMetadata { .. }
                    ) {
                        // failed to verify, try the next trust root
                        last_error = ErrorKind::from(error);
                    } else {
                        // other errors are fatal
                        return Err(Error::from(error));
                    }
                }
            }
        }
        Err(last_error.into())
    }
}
