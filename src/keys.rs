use std::{collections::HashMap, fs::File, path::Path};

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::KEYRING_VERSION;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRingFile {
    version: String,
    current_kid: String,
    keys: Vec<KeySpec>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeySpec {
    kid: String,
    seed: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

pub struct KeyRing {
    current_kid: String,
    keys: HashMap<String, SigningKey>,
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("keyring is invalid: {0}")]
    Invalid(String),
    #[error("token signing failed")]
    Signing,
}

#[derive(Debug, Serialize)]
pub struct JwkSet {
    keys: Vec<PublicJwk>,
}

#[derive(Debug, Serialize)]
struct PublicJwk {
    kty: &'static str,
    #[serde(rename = "use")]
    usage: &'static str,
    alg: &'static str,
    kid: String,
    crv: &'static str,
    x: String,
}

impl KeyRing {
    pub fn load(path: &Path, now: DateTime<Utc>) -> Result<Self, KeyError> {
        let file = File::open(path).map_err(|error| KeyError::Invalid(error.to_string()))?;
        let input: KeyRingFile =
            serde_json::from_reader(file).map_err(|error| KeyError::Invalid(error.to_string()))?;
        if input.version != KEYRING_VERSION || input.current_kid.is_empty() || input.keys.is_empty()
        {
            return Err(invalid("unsupported or empty keyring"));
        }
        let mut keys = HashMap::new();
        let mut current_valid = false;
        for spec in input.keys {
            if spec.kid.is_empty() || spec.not_after <= spec.not_before {
                return Err(invalid("key IDs and validity windows are required"));
            }
            let seed = STANDARD
                .decode(&spec.seed)
                .map_err(|_| invalid("signing seeds must be Base64"))?;
            let seed: [u8; 32] = seed
                .try_into()
                .map_err(|_| invalid("signing seeds must decode to exactly 32 bytes"))?;
            if spec.kid == input.current_kid {
                current_valid = now >= spec.not_before && now < spec.not_after;
            }
            if now < spec.not_after
                && keys
                    .insert(spec.kid, SigningKey::from_bytes(&seed))
                    .is_some()
            {
                return Err(invalid("key IDs must be unique"));
            }
        }
        if !current_valid || !keys.contains_key(&input.current_kid) {
            return Err(invalid(
                "current signing key is missing or outside its validity window",
            ));
        }
        Ok(Self {
            current_kid: input.current_kid,
            keys,
        })
    }

    pub fn sign<T: Serialize>(&self, claims: &T) -> Result<String, KeyError> {
        let signing_key = self
            .keys
            .get(&self.current_kid)
            .ok_or_else(|| invalid("current signing key is unavailable"))?;
        let document = signing_key.to_pkcs8_der().map_err(|_| KeyError::Signing)?;
        let encoding_key = EncodingKey::from_ed_der(document.as_bytes());
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.current_kid.clone());
        encode(&header, claims, &encoding_key).map_err(|_| KeyError::Signing)
    }

    pub fn jwks(&self) -> JwkSet {
        let mut keys: Vec<_> = self
            .keys
            .iter()
            .map(|(kid, key)| PublicJwk {
                kty: "OKP",
                usage: "sig",
                alg: "EdDSA",
                kid: kid.clone(),
                crv: "Ed25519",
                x: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(key.verifying_key().as_bytes()),
            })
            .collect();
        keys.sort_by(|left, right| left.kid.cmp(&right.kid));
        JwkSet { keys }
    }
}

fn invalid(message: &str) -> KeyError {
    KeyError::Invalid(message.to_owned())
}
