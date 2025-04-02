// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result, anyhow, bail};
use buf_list::BufList;
use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, Utc};
use clap::{CommandFactory, Parser};
use flate2::bufread::GzDecoder;
use futures::TryStreamExt;
use hubtools::RawHubrisArchive;
use semver::Version;
use std::collections::BTreeMap;
use std::io::Read;
use tough::Repository;
use tufaceous_artifact::{
    ArtifactKind, ArtifactVersion, ArtifactsDocument, KnownArtifactKind,
};
use tufaceous_lib::assemble::{ArtifactManifest, OmicronRepoAssembler};
use tufaceous_lib::{
    AddArtifact, ArchiveExtractor, Key, OmicronRepo, ROT_ARCHIVE_A_FILE_NAME,
    ROT_ARCHIVE_B_FILE_NAME,
};

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
        let repo_path = match self.repo {
            Some(repo) => repo,
            None => std::env::current_dir()?.try_into()?,
        };

        match self.command {
            Command::Init { system_version, no_generate_key } => {
                let keys = maybe_generate_keys(self.keys, no_generate_key)?;

                let repo = OmicronRepo::initialize(
                    log,
                    &repo_path,
                    system_version,
                    keys,
                    self.expiry,
                )
                .await?;
                slog::info!(
                    log,
                    "Initialized TUF repository in {}",
                    repo.repo_path()
                );
                Ok(())
            }
            Command::Add {
                kind,
                allow_unknown_kinds,
                path,
                name,
                version,
                allow_non_semver,
            } => {
                if !allow_unknown_kinds {
                    // Try converting kind to a known kind.
                    if kind.to_known().is_none() {
                        // Simulate a failure to parse (though ideally there would
                        // be a way to also specify the underlying error -- there
                        // doesn't appear to be a public API to do so in clap 4).
                        let mut error = clap::Error::new(
                            clap::error::ErrorKind::ValueValidation,
                        )
                        .with_cmd(&Args::command());
                        error.insert(
                            clap::error::ContextKind::InvalidArg,
                            clap::error::ContextValue::String(
                                "<KIND>".to_owned(),
                            ),
                        );
                        error.insert(
                            clap::error::ContextKind::InvalidValue,
                            clap::error::ContextValue::String(kind.to_string()),
                        );
                        error.exit();
                    }
                }

                if !allow_non_semver {
                    if let Err(error) = version.as_str().parse::<Version>() {
                        let error = Args::command().error(
                            clap::error::ErrorKind::ValueValidation,
                            format!(
                                "version `{version}` is not valid semver \
                                 (pass in --allow-non-semver to override): {error}"
                            ),
                        );
                        error.exit();
                    }
                }

                let repo = OmicronRepo::load_untrusted_ignore_expiration(
                    log, &repo_path,
                )
                .await?;
                let mut editor = repo.into_editor().await?;

                let new_artifact =
                    AddArtifact::from_path(kind, name, version, path)?;

                editor
                    .add_artifact(&new_artifact)
                    .context("error adding artifact")?;
                editor.sign_and_finish(self.keys, self.expiry).await?;
                println!(
                    "added {} {}, version {}",
                    new_artifact.kind(),
                    new_artifact.name(),
                    new_artifact.version()
                );
                Ok(())
            }
            Command::Archive { output_path } => {
                // The filename must end with "zip".
                if output_path.extension() != Some("zip") {
                    bail!("output path `{output_path}` must end with .zip");
                }

                let repo = OmicronRepo::load_untrusted_ignore_expiration(
                    log, &repo_path,
                )
                .await?;
                repo.archive(&output_path)?;

                Ok(())
            }
            Command::Extract { archive_file, dest } => {
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
                repo.read_artifacts().await.with_context(|| {
                    format!(
                        "error loading {} from extracted archive \
                         at `{dest}`",
                        ArtifactsDocument::FILE_NAME
                    )
                })?;

                Ok(())
            }
            Command::Artifacts => {
                show_artifacts(log, &repo_path).await.with_context(|| {
                    format!("error showing repository at `{repo_path}`")
                })
            }
            Command::Assemble {
                manifest_path,
                output_path,
                build_dir,
                no_generate_key,
                skip_all_present,
                allow_non_semver,
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
                    output_path,
                );
                if let Some(dir) = build_dir {
                    assembler.set_build_dir(dir);
                }

                assembler.build().await?;

                Ok(())
            }
        }
    }
}

#[derive(Debug, Parser)]
enum Command {
    /// Create a new rack update TUF repository
    Init {
        /// The system version.
        system_version: Version,

        /// Disable random key generation and exit if no keys are provided
        #[clap(long)]
        no_generate_key: bool,
    },
    Add {
        /// The kind of artifact this is.
        kind: ArtifactKind,

        /// Allow artifact kinds that aren't known to tufaceous
        #[clap(long)]
        allow_unknown_kinds: bool,

        /// Path to the artifact.
        path: Utf8PathBuf,

        /// Override the name for this artifact (default: filename with extension stripped)
        #[clap(long)]
        name: Option<String>,

        /// Artifact version.
        ///
        /// This is required to be semver by default, but can be overridden with
        /// --allow-non-semver.
        version: ArtifactVersion,

        /// Allow versions to be non-semver.
        ///
        /// Transitional option for v13 -> v14. After v14, versions will be
        /// allowed to be non-semver by default.
        #[clap(long)]
        allow_non_semver: bool,
    },
    /// Archives this repository to a zip file.
    Archive {
        /// The path to write the archive to (must end with .zip).
        output_path: Utf8PathBuf,
    },
    /// Validates and extracts a repository created by the `archive` command.
    Extract {
        /// The file to extract.
        archive_file: Utf8PathBuf,

        /// The destination to extract the file to.
        dest: Utf8PathBuf,
    },
    /// Summarizes the artifacts of an Omicron TUF repository
    Artifacts,
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

struct ArtifactInfo {
    artifact_name: String,
    artifact_version: ArtifactVersion,
    artifact_kind: ArtifactKind,
    artifact_target: String,
    details: ArtifactInfoDetails,
}

enum ArtifactInfoDetails {
    SpHubrisArchive(CommonCabooseInfo),
    RotArtifact { a: RotCabooseInfo, b: RotCabooseInfo },
    RotBootloaderArchive(RotCabooseInfo),
    NoDetails,
}

struct CommonCabooseInfo {
    board: String,
    git_commit: String,
    version: String,
    name: String,
}

struct RotCabooseInfo {
    board: String,
    // We don't currently use this but it's here for consistency and in case we
    // need it in the future.
    #[allow(dead_code)]
    git_commit: String,
    version: String,
    name: String,
    sign: String,
}

async fn show_artifacts(
    log: &slog::Logger,
    repo_path: &Utf8Path,
) -> Result<()> {
    let omicron_repo =
        OmicronRepo::load_untrusted_ignore_expiration(log, repo_path)
            .await
            .context("loading repository")?;
    let tuf_repo = omicron_repo.repo();
    let artifacts_document = omicron_repo
        .read_artifacts()
        .await
        .context("reading artifacts document")?;

    let mut sp_artifacts = Vec::new();
    let mut rot_artifacts = Vec::new();
    let mut other_artifacts = Vec::new();
    let mut rot_bootloader_artifacts = Vec::new();

    for artifact_metadata in &artifacts_document.artifacts {
        eprintln!("loading artifact {}", artifact_metadata.target);
        let known_artifact_kind =
            artifact_metadata.kind.to_known().ok_or_else(|| {
                anyhow!("unknown artifact kind: {}", &artifact_metadata.kind)
            })?;
        let (details, list) = match known_artifact_kind {
            KnownArtifactKind::GimletSp
            | KnownArtifactKind::PscSp
            | KnownArtifactKind::SwitchSp => (
                // This target is itself a Hubris archive.
                ArtifactInfoDetails::SpHubrisArchive(
                    load_caboose(&artifact_metadata.target, tuf_repo).await?,
                ),
                &mut sp_artifacts,
            ),
            KnownArtifactKind::GimletRot
            | KnownArtifactKind::PscRot
            | KnownArtifactKind::SwitchRot => {
                let details =
                    load_rot(&artifact_metadata.target, tuf_repo).await?;
                (details, &mut rot_artifacts)
            }
            KnownArtifactKind::GimletRotBootloader
            | KnownArtifactKind::PscRotBootloader
            | KnownArtifactKind::SwitchRotBootloader => (
                ArtifactInfoDetails::RotBootloaderArchive(
                    load_rot_bootloader_caboose(
                        &artifact_metadata.target,
                        tuf_repo,
                    )
                    .await?,
                ),
                &mut rot_bootloader_artifacts,
            ),
            KnownArtifactKind::Host
            | KnownArtifactKind::Trampoline
            | KnownArtifactKind::ControlPlane
            | KnownArtifactKind::Zone => {
                (ArtifactInfoDetails::NoDetails, &mut other_artifacts)
            }
        };

        let artifact_info = ArtifactInfo {
            artifact_name: artifact_metadata.name.clone(),
            artifact_version: artifact_metadata.version.clone(),
            artifact_kind: artifact_metadata.kind.clone(),
            artifact_target: artifact_metadata.target.clone(),
            details,
        };

        if artifact_metadata.target
            != format!(
                "{}-{}-{}.tar.gz",
                artifact_metadata.kind,
                artifact_metadata.name,
                artifact_metadata.version
            )
        {
            eprintln!(
                "warning: expected artifact target name to be \
                 KIND-NAME-VERSION.tar.gz"
            );
        }

        list.push(artifact_info);
    }

    println!("System Version: {}", artifacts_document.system_version);

    println!("\nSP Artifacts (Hubris archives)\n");
    println!("    {:37} {:9} {:13} {:7}", "TARGET", "KIND", "NAME", "VERSION");
    for artifact_info in &sp_artifacts {
        let ArtifactInfoDetails::SpHubrisArchive(caboose_info) =
            &artifact_info.details
        else {
            panic!("internal type mismatch");
        };

        // Only print fields that we don't expect are duplicated or otherwise
        // uninteresting (like the Git commit).  If we're wrong about these
        // being duplicated, we'll print a warning below.
        println!(
            "    {:37} {:>9} {:13} {:>7}",
            artifact_info.artifact_target,
            artifact_info.artifact_kind,
            artifact_info.artifact_name,
            artifact_info.artifact_version,
        );

        if caboose_info.version != artifact_info.artifact_version.as_str() {
            eprintln!(
                "warning: target {}: caboose version {} does not match \
                 artifact version {}",
                artifact_info.artifact_target,
                caboose_info.version,
                artifact_info.artifact_version
            );
        }

        // XXX-dap There is a comment on
        // `tufaceous_artifact::artifact::Artifact` that says that the `name`
        // should match the caboose *board*.  That's not true: SP artifacts
        // sometimes (but not always) have a signing key ("lab") in the artifact
        // name.
        if caboose_info.board != artifact_info.artifact_name
            && format!("{}-lab", caboose_info.board)
                != artifact_info.artifact_name
        {
            eprintln!(
                "warning: target {}: caboose board {} does not match \
                 artifact name {}",
                artifact_info.artifact_target,
                caboose_info.board,
                artifact_info.artifact_name,
            );
        }

        // See above comment.
        if caboose_info.name != artifact_info.artifact_name {
            eprintln!(
                "warning: target {}: caboose name {} does not match \
                 artifact name {}",
                artifact_info.artifact_target,
                caboose_info.name,
                artifact_info.artifact_name,
            );
        }
    }

    // XXX-dap
    let known_signature_names: BTreeMap<&str, &str> = [
        (
            "84332ef8279df87fbb759dc3866cbc50cd246fbb5a64705a7e60ba86bf01c27d",
            "bart",
        ),
        (
            "11594bb5548a757e918e6fe056e2ad9e084297c9555417a025d8788eacf55daf",
            "gimlet-staging-devel",
        ),
        (
            "5796ee3433f840519c3bcde73e19ee82ccb6af3857eddaabb928b8d9726d93c0",
            "gimlet-production-release",
        ),
        (
            "f592d8f109b81881221eed5af6438abad9b5df8c220b9129c03763e7e10b22c7",
            "psc-staging-devel",
        ),
        (
            "31942f8d53dc908c5cb338bdcecb204785fa87834e8b18f706fc972a42886c8b",
            "psc-production-release",
        ),
        (
            "1432cc4cfe5688c51b55546fe37837c753cfbc89e8c3c6aabcf977fdf0c41e27",
            "switch-staging-devel",
        ),
        (
            "5c69a42ee1f1e6cd5f356d14f81d46f8dbee783bb28777334226c689f169c0eb",
            "switch-production-release",
        ),
    ]
    .into_iter()
    .collect();

    println!("\nRoT Bootloader Artifacts\n");
    println!(
        "    {:75} {:21} {:40} {:7} {:25}",
        "TARGET", "KIND", "NAME", "VERSION", "SIGNING KEY"
    );
    for artifact_info in &rot_bootloader_artifacts {
        let ArtifactInfoDetails::RotBootloaderArchive(rot_caboose) =
            &artifact_info.details
        else {
            panic!("internal type mismatch");
        };

        let key_name =
            known_signature_names.get(rot_caboose.sign.as_str()).copied();

        // Only print fields that we don't expect are duplicated or otherwise
        // uninteresting (like the Git commit).  If we're wrong about these
        // being duplicated, we'll print a warning below.
        println!(
            "    {:75} {:>21} {:40} {:>7} {:25}",
            artifact_info.artifact_target,
            artifact_info.artifact_kind,
            artifact_info.artifact_name,
            artifact_info.artifact_version,
            key_name.unwrap_or("UNKNOWN"),
        );

        if rot_caboose.board != rot_caboose.name {
            eprintln!(
                "warning: expected caboose \"board\" and \"name\" \
                 to be the same, but they're not"
            );
        }

        if key_name.is_none() {
            eprintln!("warning: unrecognized \"sign\"");
        }

        if rot_caboose.version != artifact_info.artifact_version.as_str() {
            eprintln!(
                "warning: caboose version {} does not match \
                     artifact version {}",
                rot_caboose.version, artifact_info.artifact_version
            );
        }

        // XXX-dap
        // See the similar comment above.  RoT images sometimes have their
        // key ("selfsigned-bart", "production-release", or "staging-devel")
        // tacked onto the end of the board name in their artifact name.
        // XXX-dap verify my assumptions here
        // if caboose_info.board != artifact_info.artifact_name
        //     && format!("{}-lab", caboose_info.board)
        //         != artifact_info.artifact_name
        // {
        //     eprintln!(
        //         "warning: target {}: caboose board {} does not match \
        //          artifact name {}",
        //         artifact_info.artifact_target,
        //         caboose_info.board,
        //         artifact_info.artifact_name,
        //     );
        // }

        // XXX-dap
        // See above comment.  Similarly, the artifact name sometimes has
        // keys appended to it.
        // if caboose_info.name != artifact_info.artifact_name {
        //     eprintln!(
        //         "warning: target {}: caboose name {} does not match \
        //          artifact name {}",
        //         artifact_info.artifact_target,
        //         caboose_info.name,
        //         artifact_info.artifact_name,
        //     );
        // }
    }

    println!(
        "\nRoT Artifacts (composite artifacts with two Hubris archives)\n"
    );
    println!(
        "    {:61} {:10} {:36} {:7} {:25}",
        "TARGET", "KIND", "NAME", "VERSION", "SIGNING KEY"
    );
    for artifact_info in &rot_artifacts {
        let ArtifactInfoDetails::RotArtifact { a, b } = &artifact_info.details
        else {
            panic!("internal type mismatch");
        };

        let key_name = known_signature_names.get(a.sign.as_str()).copied();

        // Only print fields that we don't expect are duplicated or otherwise
        // uninteresting (like the Git commit).  If we're wrong about these
        // being duplicated, we'll print a warning below.
        println!(
            "    {:61} {:>10} {:36} {:>7} {:25}",
            artifact_info.artifact_target,
            artifact_info.artifact_kind,
            artifact_info.artifact_name,
            artifact_info.artifact_version,
            key_name.unwrap_or("UNKNOWN"),
        );

        if a.board != a.name {
            eprintln!(
                "warning: archive a: expected caboose \"board\" and \"name\" \
                 to be the same, but they're not"
            );
        }

        if b.board != b.name {
            eprintln!(
                "warning: archive a: expected caboose \"board\" and \"name\" \
                 to be the same, but they're not"
            );
        }

        if a.sign != b.sign {
            eprintln!(
                "warning: expected archives A and B to have the same \"sign\""
            );
        }

        if key_name.is_none() {
            eprintln!("warning: unrecognized \"sign\"");
        }

        for caboose_info in [a, b] {
            if caboose_info.version != artifact_info.artifact_version.as_str() {
                eprintln!(
                    "warning: target {}: caboose version {} does not match \
                     artifact version {}",
                    artifact_info.artifact_target,
                    caboose_info.version,
                    artifact_info.artifact_version
                );
            }

            // XXX-dap
            // See the similar comment above.  RoT images sometimes have their
            // key ("selfsigned-bart", "production-release", or "staging-devel")
            // tacked onto the end of the board name in their artifact name.
            // XXX-dap verify my assumptions here
            // if caboose_info.board != artifact_info.artifact_name
            //     && format!("{}-lab", caboose_info.board)
            //         != artifact_info.artifact_name
            // {
            //     eprintln!(
            //         "warning: target {}: caboose board {} does not match \
            //          artifact name {}",
            //         artifact_info.artifact_target,
            //         caboose_info.board,
            //         artifact_info.artifact_name,
            //     );
            // }

            // XXX-dap
            // See above comment.  Similarly, the artifact name sometimes has
            // keys appended to it.
            // if caboose_info.name != artifact_info.artifact_name {
            //     eprintln!(
            //         "warning: target {}: caboose name {} does not match \
            //          artifact name {}",
            //         artifact_info.artifact_target,
            //         caboose_info.name,
            //         artifact_info.artifact_name,
            //     );
            // }
        }
    }

    println!("\nOther artifacts\n");
    println!(
        "    {:61} {:13} {:13} {:26}",
        "TARGET", "KIND", "NAME", "VERSION"
    );
    for artifact_info in &other_artifacts {
        println!(
            "    {:61} {:13} {:13} {:26}",
            artifact_info.artifact_target,
            artifact_info.artifact_kind,
            artifact_info.artifact_name,
            artifact_info.artifact_version,
        );
    }

    // XXX-dap print out other file kinds

    Ok(())
}

async fn load_caboose(
    target_name: &str,
    tuf_repo: &Repository,
) -> Result<CommonCabooseInfo> {
    load_caboose_impl(target_name, tuf_repo).await.with_context(|| {
        format!("loading caboose for target {:?}", target_name)
    })
}

async fn load_caboose_impl(
    target_name: &str,
    tuf_repo: &Repository,
) -> Result<CommonCabooseInfo> {
    let v = load_target_bytes(target_name, tuf_repo).await?;
    load_caboose_from_archive_bytes(v).await
}

async fn load_caboose_from_archive_bytes(
    v: Vec<u8>,
) -> Result<CommonCabooseInfo> {
    let archive =
        RawHubrisArchive::from_vec(v).context("loading Hubris archive")?;
    let caboose = archive.read_caboose().context("loading caboose")?;
    load_caboose_common_fields(&caboose)
}

fn load_caboose_common_fields(
    caboose: &hubtools::Caboose,
) -> Result<CommonCabooseInfo> {
    let name = String::from_utf8(
        caboose.name().context("reading name from caboose")?.to_vec(),
    )
    .context("unexpected non-UTF8 name")?;
    let board = String::from_utf8(
        caboose.board().context("reading board from caboose")?.to_vec(),
    )
    .context("unexpected non-UTF8 board")?;
    let git_commit = String::from_utf8(
        caboose
            .git_commit()
            .context("reading git_commit from caboose")?
            .to_vec(),
    )
    .context("unexpected non-UTF8 git_commit")?;
    let version = String::from_utf8(
        caboose.version().context("reading version from caboose")?.to_vec(),
    )
    .context("unexpected non-UTF8 version")?;
    Ok(CommonCabooseInfo { board, git_commit, version, name })
}

async fn load_rot_bootloader_caboose(
    target_name: &str,
    tuf_repo: &Repository,
) -> Result<RotCabooseInfo> {
    load_rot_bootloader_caboose_impl(target_name, tuf_repo).await.with_context(
        || format!("loading caboose for target {:?}", target_name),
    )
}

async fn load_rot_bootloader_caboose_impl(
    target_name: &str,
    tuf_repo: &Repository,
) -> Result<RotCabooseInfo> {
    let v = load_target_bytes(target_name, tuf_repo).await?;
    load_rot_caboose_from_archive_bytes(v).await
}

async fn load_rot_caboose_from_archive_bytes(
    v: Vec<u8>,
) -> Result<RotCabooseInfo> {
    let archive =
        RawHubrisArchive::from_vec(v).context("loading Hubris archive")?;
    let caboose = archive.read_caboose().context("loading caboose")?;
    let sign = String::from_utf8(
        caboose.sign().context("reading sign from caboose")?.to_vec(),
    )
    .context("unexpected non-UTF8 sign")?;
    let common = load_caboose_common_fields(&caboose)?;
    Ok(RotCabooseInfo {
        board: common.board,
        git_commit: common.git_commit,
        version: common.version,
        name: common.name,
        sign,
    })
}

// XXX-dap this could return a reader and then the tar thing wouldn't need to
// load the whole thing into memory at once
async fn load_target_bytes(
    target_name: &str,
    tuf_repo: &Repository,
) -> Result<Vec<u8>> {
    let target_name: tough::TargetName =
        target_name.parse().context("unsupported target name")?;
    let reader = tuf_repo
        .read_target(&target_name)
        .await
        .context("loading target")?
        .ok_or_else(|| anyhow!("missing target"))?;
    let buf_list =
        reader.try_collect::<BufList>().await.context("reading target")?;
    let v: Vec<u8> = buf_list.into_iter().flatten().collect();
    Ok(v)
}

async fn load_rot(
    target_name: &str,
    tuf_repo: &Repository,
) -> Result<ArtifactInfoDetails> {
    load_rot_impl(target_name, tuf_repo)
        .await
        .with_context(|| anyhow!("loading RoT target {}", target_name))
}

async fn load_rot_impl(
    target_name: &str,
    tuf_repo: &Repository,
) -> Result<ArtifactInfoDetails> {
    let v = load_target_bytes(target_name, tuf_repo).await?;
    let source = std::io::BufReader::new(std::io::Cursor::new(v));
    let gunzip = GzDecoder::new(source);
    let mut tar = tar::Archive::new(gunzip);
    let mut caboose_a = None;
    let mut caboose_b = None;

    for entry in tar.entries().context("reading tarball")? {
        let mut entry = entry.context("reading entry from tarball")?;
        let path =
            entry.path().context("reading path for entry from tarball")?;
        let Some(basename) = path.file_name() else {
            continue;
        };
        let caboose_which = if basename == ROT_ARCHIVE_A_FILE_NAME {
            &mut caboose_a
        } else if basename == ROT_ARCHIVE_B_FILE_NAME {
            &mut caboose_b
        } else {
            continue;
        };

        let mut s = Vec::with_capacity(
            usize::try_from(
                entry
                    .header()
                    .size()
                    .context("corrupted tarball entry size")?,
            )
            .context("archive size too large")?,
        );
        entry.read_to_end(&mut s).context("reading entry")?;
        *caboose_which = Some(load_rot_caboose_from_archive_bytes(s).await?);
    }

    match (caboose_a, caboose_b) {
        (Some(a), Some(b)) => Ok(ArtifactInfoDetails::RotArtifact { a, b }),
        _ => Err(anyhow!("missing expected RoT artifact")),
    }
}
