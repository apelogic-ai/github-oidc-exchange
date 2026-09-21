//! Offline keyring administration. Private material is written only to mode-0600 files.
use std::{
    env,
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use github_oidc_exchange::{
    KEYRING_VERSION, RSA_KEYRING_VERSION,
    keys::{KeyRing, RsaKeyRing},
};
use p256::SecretKey;
use rand_core::OsRng;
use rsa::{RsaPrivateKey, pkcs8::EncodePrivateKey};
use serde_json::{Value, json};

fn main() {
    if let Err(error) = run() {
        eprintln!("keyring-tool: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    if !(2..=3).contains(&args.len()) {
        return Err(
            "usage: keyring-tool (generate|validate|add|activate|retire)-(es256|rsa) FILE [KID]"
                .into(),
        );
    }
    let (action, algorithm) = args[0]
        .rsplit_once('-')
        .ok_or("command must end in -es256 or -rsa")?;
    if algorithm != "es256" && algorithm != "rsa" {
        return Err("algorithm must be es256 or rsa".into());
    }
    let needs_kid = action != "validate";
    if args.len() != if needs_kid { 3 } else { 2 } {
        return Err("this command has the wrong number of arguments".into());
    }
    let path = Path::new(&args[1]);
    if needs_kid {
        validate_kid(&args[2])?;
    }
    match action {
        "generate" => {
            if fs::symlink_metadata(path).is_ok() {
                return Err("target keyring already exists; refusing overwrite".into());
            }
            let document = json!({
                "version": version(algorithm),
                "current_kid": args[2],
                "keys": [new_key(algorithm, &args[2])?],
            });
            write_private(path, &document, false)?;
        }
        "validate" => {
            validate_private(path, algorithm)?;
        }
        "add" | "activate" | "retire" => {
            validate_private(path, algorithm)?;
            let mut document: Value = serde_json::from_slice(&fs::read(path)?)?;
            let keys = document["keys"]
                .as_array_mut()
                .ok_or("keys must be an array")?;
            let exists = keys.iter().any(|key| key["kid"] == args[2]);
            match action {
                "add" => {
                    if exists {
                        return Err("key ID already exists".into());
                    }
                    keys.push(new_key(algorithm, &args[2])?);
                }
                "activate" => {
                    if !exists {
                        return Err("key ID is not present".into());
                    }
                    document["current_kid"] = Value::String(args[2].clone());
                }
                "retire" => {
                    if document["current_kid"] == args[2] {
                        return Err("cannot retire the current signing key".into());
                    }
                    if !exists {
                        return Err("key ID is not present".into());
                    }
                    document["keys"]
                        .as_array_mut()
                        .ok_or("keys must be an array")?
                        .retain(|key| key["kid"] != args[2]);
                }
                _ => unreachable!(),
            }
            write_private(path, &document, true)?;
        }
        _ => return Err("unknown command".into()),
    }
    println!("{action} {algorithm}: ok");
    Ok(())
}

fn version(algorithm: &str) -> &'static str {
    if algorithm == "es256" {
        KEYRING_VERSION
    } else {
        RSA_KEYRING_VERSION
    }
}

fn validate_kid(kid: &str) -> Result<(), Box<dyn Error>> {
    if kid.is_empty()
        || kid.len() > 64
        || !kid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("KID must be 1-64 ASCII letters, digits, dot, underscore, or hyphen".into());
    }
    Ok(())
}

fn new_key(algorithm: &str, kid: &str) -> Result<Value, Box<dyn Error>> {
    let now = Utc::now();
    let before = now - Duration::minutes(5);
    let after = now + Duration::days(90);
    if algorithm == "es256" {
        let key = SecretKey::random(&mut OsRng);
        Ok(json!({
            "kid": kid,
            "seed": STANDARD.encode(key.to_bytes()),
            "not_before": before,
            "not_after": after,
        }))
    } else {
        let key = RsaPrivateKey::new(&mut OsRng, 3072)?;
        let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?;
        Ok(json!({
            "kid": kid,
            "private_key_pkcs8_pem": pem.as_str(),
            "not_before": before,
            "not_after": after,
        }))
    }
}

fn validate_private(path: &Path, algorithm: &str) -> Result<(), Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err("keyring must be a regular mode-0600 file".into());
    }
    if algorithm == "es256" {
        KeyRing::load(path, Utc::now())?;
    } else {
        RsaKeyRing::load(path, Utc::now())?;
    }
    Ok(())
}

fn write_private(path: &Path, document: &Value, replace: bool) -> Result<(), Box<dyn Error>> {
    let parent = path
        .parent()
        .ok_or("keyring path needs a parent directory")?;
    if !parent.is_dir() || (!replace && fs::symlink_metadata(path).is_ok()) {
        return Err("parent directory missing or target already exists".into());
    }
    let temp = parent.join(format!(".keyring-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<(), Box<dyn Error>> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        serde_json::to_writer_pretty(&mut file, document)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        let algorithm = if document["version"] == KEYRING_VERSION {
            "es256"
        } else {
            "rsa"
        };
        validate_private(&temp, algorithm)?;
        if !replace && fs::symlink_metadata(path).is_ok() {
            return Err("target appeared while generating; refusing overwrite".into());
        }
        fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
