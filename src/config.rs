use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Config {
    pub issuer_url: String,
    pub github_exchange_audience: String,
    pub output_audience: String,
    pub policy_file: PathBuf,
    pub keyring_file: PathBuf,
    pub replay_table: String,
    pub listen_address: SocketAddr,
    pub token_ttl: Duration,
    pub workload: Option<WorkloadConfig>,
}

#[derive(Clone, Debug)]
pub struct WorkloadConfig {
    pub listen_address: SocketAddr,
    pub input_audience: String,
    pub output_audience: String,
    pub policy_file: PathBuf,
    pub rsa_keyring_file: PathBuf,
    pub tls_certificate_file: PathBuf,
    pub tls_private_key_file: PathBuf,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("required environment variable {0} is missing")]
    Missing(&'static str),
    #[error("ISSUER_URL must be an absolute HTTPS URL without a query or fragment")]
    InvalidIssuer,
    #[error("OUTPUT_AUDIENCE must be steward-task-api")]
    InvalidOutputAudience,
    #[error("LISTEN_ADDRESS is invalid")]
    InvalidListenAddress,
    #[error("WORKLOAD_LISTEN_ADDRESS is invalid")]
    InvalidWorkloadListenAddress,
    #[error("public and workload listeners must use different addresses")]
    ConflictingListenAddresses,
    #[error("WORKLOAD_EXCHANGE_ENABLED must be true or false")]
    InvalidWorkloadEnabled,
    #[error("WORKLOAD_OUTPUT_AUDIENCE must be openshell-api")]
    InvalidWorkloadOutputAudience,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let issuer_url = required("ISSUER_URL")?.trim_end_matches('/').to_owned();
        let parsed = reqwest::Url::parse(&issuer_url).map_err(|_| ConfigError::InvalidIssuer)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ConfigError::InvalidIssuer);
        }
        let output_audience = required("OUTPUT_AUDIENCE")?;
        if output_audience != "steward-task-api" {
            return Err(ConfigError::InvalidOutputAudience);
        }
        let listen_address = env::var("LISTEN_ADDRESS")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_owned())
            .parse()
            .map_err(|_| ConfigError::InvalidListenAddress)?;
        let workload = WorkloadConfig::from_env(listen_address)?;
        Ok(Self {
            issuer_url,
            github_exchange_audience: required("GITHUB_EXCHANGE_AUDIENCE")?,
            output_audience,
            policy_file: PathBuf::from(required("POLICY_FILE")?),
            keyring_file: PathBuf::from(required("KEYRING_FILE")?),
            replay_table: required("REPLAY_TABLE")?,
            listen_address,
            token_ttl: Duration::from_secs(120),
            workload,
        })
    }
}

impl WorkloadConfig {
    pub fn from_env(public_listen_address: SocketAddr) -> Result<Option<Self>, ConfigError> {
        let workload_enabled = match env::var("WORKLOAD_EXCHANGE_ENABLED").as_deref() {
            Ok("true") => true,
            Ok("false") | Err(env::VarError::NotPresent) => false,
            Ok(_) | Err(env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::InvalidWorkloadEnabled);
            }
        };
        let workload = if workload_enabled {
            let output_audience = required("WORKLOAD_OUTPUT_AUDIENCE")?;
            if output_audience != "openshell-api" {
                return Err(ConfigError::InvalidWorkloadOutputAudience);
            }
            Some(WorkloadConfig {
                listen_address: env::var("WORKLOAD_LISTEN_ADDRESS")
                    .unwrap_or_else(|_| "0.0.0.0:8443".to_owned())
                    .parse()
                    .map_err(|_| ConfigError::InvalidWorkloadListenAddress)?,
                input_audience: required("WORKLOAD_INPUT_AUDIENCE")?,
                output_audience,
                policy_file: PathBuf::from(required("WORKLOAD_POLICY_FILE")?),
                rsa_keyring_file: PathBuf::from(required("WORKLOAD_RSA_KEYRING_FILE")?),
                tls_certificate_file: PathBuf::from(required("TLS_CERTIFICATE_FILE")?),
                tls_private_key_file: PathBuf::from(required("TLS_PRIVATE_KEY_FILE")?),
            })
        } else {
            None
        };
        if workload
            .as_ref()
            .is_some_and(|workload| workload.listen_address == public_listen_address)
        {
            return Err(ConfigError::ConflictingListenAddresses);
        }
        Ok(workload)
    }
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(ConfigError::Missing(name))
}
