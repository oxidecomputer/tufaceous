// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use assert_cmd::Command;
use dropshot::test_util::LogContext;
use dropshot::{ConfigLogging, ConfigLoggingIfExists, ConfigLoggingLevel};
use predicates::prelude::*;
use tufaceous_lib::Key;

#[test]
fn test_assemble_fake() -> Result<()> {
    let log_config = ConfigLogging::File {
        level: ConfigLoggingLevel::Trace,
        path: "UNUSED".into(),
        if_exists: ConfigLoggingIfExists::Fail,
    };
    let logctx = LogContext::new("test_assemble_fake", &log_config);
    let tempdir = tempfile::tempdir().unwrap();
    let key = Key::generate_ed25519()?;

    let archive_path = tempdir.path().join("archive.zip");

    let mut cmd = make_cmd(&key);
    cmd.args(["assemble", "manifests/fake.toml"]);
    cmd.arg(&archive_path);
    cmd.assert().success();

    // Extract the archive to a new directory.
    let dest_path = tempdir.path().join("dest");
    let mut cmd = make_cmd(&key);
    cmd.arg("extract");
    cmd.arg(&archive_path);
    cmd.arg(&dest_path);

    cmd.assert().success();

    logctx.cleanup_successful();
    Ok(())
}

#[test]
fn test_assemble_fake_non_semver() -> Result<()> {
    let log_config = ConfigLogging::File {
        level: ConfigLoggingLevel::Trace,
        path: "UNUSED".into(),
        if_exists: ConfigLoggingIfExists::Fail,
    };
    let logctx = LogContext::new("test_assemble_fake_non_semver", &log_config);
    let tempdir = tempfile::tempdir().unwrap();
    let key = Key::generate_ed25519()?;

    let archive_path = tempdir.path().join("archive.zip");

    let mut cmd = make_cmd(&key);
    cmd.args(["assemble", "manifests/fake-non-semver.toml"]);
    cmd.arg(&archive_path);
    cmd.assert().failure().stderr(predicate::str::contains(
        "non-semver versions found: fake-trampoline (non-semver), \
         fake-switch-rot-bootloader (non-semver-2)",
    ));

    let mut cmd = make_cmd(&key);
    cmd.args([
        "assemble",
        "manifests/fake-non-semver.toml",
        "--allow-non-semver",
    ]);
    cmd.arg(&archive_path);
    cmd.assert().success();

    // Extract the archive to a new directory.
    let dest_path = tempdir.path().join("dest");
    let mut cmd = make_cmd(&key);
    cmd.arg("extract");
    cmd.arg(&archive_path);
    cmd.arg(&dest_path);

    cmd.assert().success();

    logctx.cleanup_successful();
    Ok(())
}

#[test]
fn test_assemble_duplicate_zone() -> Result<()> {
    let log_config = ConfigLogging::File {
        level: ConfigLoggingLevel::Trace,
        path: "UNUSED".into(),
        if_exists: ConfigLoggingIfExists::Fail,
    };
    let logctx = LogContext::new("test_assemble_duplicate_zone", &log_config);
    let tempdir = tempfile::tempdir().unwrap();
    let key = Key::generate_ed25519()?;

    let archive_path = tempdir.path().join("archive.zip");

    let mut cmd = make_cmd(&key);
    cmd.args([
        "assemble",
        "--skip-all-present",
        // TODO: should we also check duplicate zone artifact names?
        "invalid-manifests/duplicate-zone-file-name.toml",
    ]);
    cmd.arg(&archive_path);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(
            r#"a deployment unit with the same kind and hash already exists in this control_plane artifact:"#,
        ))
        .stderr(predicate::str::contains("zone/"))
        .stderr(predicate::str::contains(
            r#"(existing name: zone1.tar.gz, version: 1.0.0; new name: zone1-dup.tar.gz, version: 1.0.0)"#,
        ));

    logctx.cleanup_successful();
    Ok(())
}

#[test]
fn test_assemble_duplicate_artifact() -> Result<()> {
    let log_config = ConfigLogging::File {
        level: ConfigLoggingLevel::Trace,
        path: "UNUSED".into(),
        if_exists: ConfigLoggingIfExists::Fail,
    };
    let logctx =
        LogContext::new("test_assemble_duplicate_artifact", &log_config);
    let tempdir = tempfile::tempdir().unwrap();
    let key = Key::generate_ed25519()?;

    let archive_path = tempdir.path().join("archive.zip");

    let mut cmd = make_cmd(&key);
    cmd.args([
        "assemble",
        "--skip-all-present",
        "invalid-manifests/duplicate-artifact.toml",
    ]);
    cmd.arg(&archive_path);
    cmd.assert().failure().stderr(predicate::str::contains(
        "a target named gimlet_sp-fake-gimlet-sp-1.0.0.tar.gz \
         already exists in the repository",
    ));

    logctx.cleanup_successful();
    Ok(())
}

#[test]
fn test_assemble_duplicate_artifact_2() -> Result<()> {
    let log_config = ConfigLogging::File {
        level: ConfigLoggingLevel::Trace,
        path: "UNUSED".into(),
        if_exists: ConfigLoggingIfExists::Fail,
    };
    let logctx =
        LogContext::new("test_assemble_duplicate_artifact_2", &log_config);
    let tempdir = tempfile::tempdir().unwrap();
    let key = Key::generate_ed25519()?;

    let archive_path = tempdir.path().join("archive.zip");

    let mut cmd = make_cmd(&key);
    cmd.args([
        "assemble",
        "--skip-all-present",
        "invalid-manifests/duplicate-artifact-2.toml",
    ]);
    cmd.arg(&archive_path);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("2 errors encountered"))
        .stderr(predicate::str::contains(
            "a deployment unit with the same kind and hash already exists \
             in this repository:",
        ))
        .stderr(predicate::str::contains("gimlet_sp/"))
        .stderr(predicate::str::contains(
            "(existing name: fake-gimlet-sp, version: 1.0.0; \
             new name: fake-gimlet-sp, version: 2.0.0)",
        ))
        .stderr(predicate::str::contains("switch_sp/"))
        .stderr(predicate::str::contains(
            "(existing name: fake-switch-sp, version: 1.0.0; \
             new name: fake-switch-sp, version: 2.0.0)",
        ));

    logctx.cleanup_successful();
    Ok(())
}

fn make_cmd(key: &Key) -> Command {
    let mut cmd = Command::cargo_bin("tufaceous").unwrap();
    cmd.env("TUFACEOUS_KEY", key.to_string());

    cmd
}
