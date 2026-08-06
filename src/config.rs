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
        Ok(Self {
            issuer_url,
            github_exchange_audience: required("GITHUB_EXCHANGE_AUDIENCE")?,
            output_audience,
            policy_file: PathBuf::from(required("POLICY_FILE")?),
            keyring_file: PathBuf::from(required("KEYRING_FILE")?),
            replay_table: required("REPLAY_TABLE")?,
            listen_address,
            token_ttl: Duration::from_secs(120),
        })
    }
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(ConfigError::Missing(name))
}
