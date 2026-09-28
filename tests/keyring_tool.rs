#![allow(clippy::expect_used)]

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    process::Command,
};

use chrono::{DateTime, Utc};
use github_oidc_exchange::keys::{KeyRing, RsaKeyRing};

fn tool(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_keyring-tool"))
        .args(args)
        .output()
        .expect("run keyring tool")
}

#[test]
fn generation_resolves_a_bare_filename_in_the_current_directory() {
    let dir = tempfile::tempdir().expect("private tempdir");
    let generated = Command::new(env!("CARGO_BIN_EXE_keyring-tool"))
        .current_dir(dir.path())
        .args(["generate-es256", "keyring.json", "initial"])
        .output()
        .expect("run keyring tool");
    assert!(generated.status.success());

    let path = dir.path().join("keyring.json");
    assert_eq!(
        fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
    assert!(KeyRing::load(&path, Utc::now()).is_ok());
}

#[test]
fn generation_reports_a_missing_parent_directory_precisely() {
    let dir = tempfile::tempdir().expect("private tempdir");
    let path = dir.path().join("missing").join("keyring.json");
    let generated = tool(&[
        "generate-es256",
        path.to_str().expect("utf8 path"),
        "initial",
    ]);
    assert!(!generated.status.success());
    assert!(
        String::from_utf8_lossy(&generated.stderr)
            .contains("keyring parent directory does not exist")
    );
}

#[test]
fn generation_and_add_accept_a_bounded_validity_period() {
    let dir = tempfile::tempdir().expect("private tempdir");
    let path = dir.path().join("issuer.json");
    let path = path.to_str().expect("utf8 path");

    assert!(
        tool(&["generate-es256", path, "initial", "--valid-for-days", "30",])
            .status
            .success()
    );
    assert!(
        tool(&["add-es256", path, "next", "--valid-for-days", "45",])
            .status
            .success()
    );
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(path).expect("keyring file")).expect("keyring JSON");
    for (kid, expected_days) in [("initial", 30), ("next", 45)] {
        let key = document["keys"]
            .as_array()
            .expect("key array")
            .iter()
            .find(|key| key["kid"] == kid)
            .expect("generated key");
        let not_before = key["not_before"]
            .as_str()
            .expect("not_before")
            .parse::<DateTime<Utc>>()
            .expect("not_before timestamp");
        let not_after = key["not_after"]
            .as_str()
            .expect("not_after")
            .parse::<DateTime<Utc>>()
            .expect("not_after timestamp");
        let validity_days = (not_after - not_before).num_days();
        assert!((i64::from(expected_days)..=i64::from(expected_days) + 1).contains(&validity_days));
    }

    for invalid_days in ["0", "3651", "not-a-number"] {
        let invalid_path = dir.path().join(format!("invalid-{invalid_days}.json"));
        assert!(
            !tool(&[
                "generate-es256",
                invalid_path.to_str().expect("utf8 path"),
                "invalid",
                "--valid-for-days",
                invalid_days,
            ])
            .status
            .success()
        );
    }
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
    let exported = tool(&["export-jwks", path]);
    assert!(exported.status.success());
    let exported: serde_json::Value =
        serde_json::from_slice(&exported.stdout).expect("public JWKS JSON");
    let exported_keys = exported["keys"].as_array().expect("public keys");
    assert_eq!(exported_keys.len(), 2);
    assert!(exported_keys.iter().all(|key| {
        key["kty"] == "EC"
            && key["alg"] == "ES256"
            && key.get("seed").is_none()
            && key.get("private_key_pkcs8_pem").is_none()
    }));
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
    assert!(!tool(&["export-jwks", path]).status.success());
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
    let exported = tool(&["export-jwks", path]);
    assert!(exported.status.success());
    assert!(!String::from_utf8_lossy(&exported.stdout).contains("PRIVATE KEY"));
    let exported: serde_json::Value =
        serde_json::from_slice(&exported.stdout).expect("public JWKS JSON");
    assert_eq!(exported["keys"][0]["kty"], "RSA");
    assert_eq!(exported["keys"][0]["alg"], "RS256");
    assert!(exported["keys"][0].get("private_key_pkcs8_pem").is_none());
    assert!(tool(&["validate-rsa", path]).status.success());
    assert!(!tool(&["validate-es256", path]).status.success());
}
