#![allow(clippy::expect_used)]

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    process::Command,
};

use chrono::Utc;
use github_oidc_exchange::keys::{KeyRing, RsaKeyRing};

fn tool(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_keyring-tool"))
        .args(args)
        .output()
        .expect("run keyring tool")
}

#[test]
fn es256_generation_validation_and_rotation_are_private_and_loadable() {
    let dir = tempfile::tempdir().expect("private tempdir");
    let path = dir.path().join("issuer.json");
    let path = path.to_str().expect("utf8 path");

    assert!(tool(&["generate-es256", path, "initial"]).status.success());
    assert_eq!(
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
    assert!(KeyRing::load(path.as_ref(), Utc::now()).is_ok());
    assert!(
        !tool(&["generate-es256", path, "overwrite"])
            .status
            .success()
    );
    assert!(tool(&["validate-es256", path]).status.success());
    assert!(tool(&["add-es256", path, "next"]).status.success());
    assert!(
        KeyRing::load(path.as_ref(), Utc::now())
            .expect("overlap")
            .contains_kid("next")
    );
    assert!(tool(&["activate-es256", path, "next"]).status.success());
    assert!(tool(&["validate-es256", path]).status.success());
    assert!(tool(&["retire-es256", path, "initial"]).status.success());
    assert!(
        !KeyRing::load(path.as_ref(), Utc::now())
            .expect("retired")
            .contains_kid("initial")
    );
    assert!(!tool(&["retire-es256", path, "next"]).status.success());
    assert_eq!(
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("change mode");
    assert!(!tool(&["validate-es256", path]).status.success());
}

#[test]
fn generation_refuses_even_a_dangling_symlink_target() {
    let dir = tempfile::tempdir().expect("private tempdir");
    let path = dir.path().join("issuer.json");
    symlink(dir.path().join("missing"), &path).expect("symlink");
    let path = path.to_str().expect("utf8 path");
    assert!(!tool(&["generate-es256", path, "initial"]).status.success());
    assert!(
        fs::symlink_metadata(path)
            .expect("metadata")
            .file_type()
            .is_symlink()
    );
}

#[test]
fn rsa_generation_is_3072_bit_and_never_prints_private_key() {
    let dir = tempfile::tempdir().expect("private tempdir");
    let path = dir.path().join("workload.json");
    let path = path.to_str().expect("utf8 path");
    let generated = tool(&["generate-rsa", path, "workload-initial"]);
    assert!(generated.status.success());
    assert!(!String::from_utf8_lossy(&generated.stdout).contains("PRIVATE KEY"));
    assert!(!String::from_utf8_lossy(&generated.stderr).contains("PRIVATE KEY"));
    assert_eq!(
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
    assert!(RsaKeyRing::load(path.as_ref(), Utc::now()).is_ok());
    assert!(tool(&["validate-rsa", path]).status.success());
    assert!(!tool(&["validate-es256", path]).status.success());
}
