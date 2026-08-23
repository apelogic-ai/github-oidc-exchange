use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Config {
    pub issuer_url: String,
    pub github_exchange_audience: String,
    pub output_audience: String,
    pub policy_file: PathBuf,
    pub keyring_file: PathBuf,
    pub replay_lease_namespace: String,
    pub listen_address: SocketAddr,
    pub token_ttl: Duration,
    pub workload: Option<WorkloadConfig>,
    pub browser_hop1: Option<BrowserHop1Config>,
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

/// Configuration for the internal-only Steward browser-session attestation exchange.
/// All source identity is verified by Steward before it signs the assertion; Identity only reads
/// its static public JWKS and never receives browser state.
#[derive(Clone, Debug)]
pub struct BrowserHop1Config {
    pub steward_issuer: String,
    pub assertion_audience: String,
    pub steward_jwks_file: PathBuf,
    pub output_audience: String,
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
    #[error("BROWSER_HOP1_ENABLED must be true or false")]
    InvalidBrowserHop1Enabled,
    #[error("browser HOP-1 requires WORKLOAD_EXCHANGE_ENABLED=true")]
    BrowserHop1RequiresWorkload,
    #[error(
        "BROWSER_HOP1_STEWARD_ISSUER must be an absolute HTTPS URL without a query or fragment"
    )]
    InvalidBrowserHop1StewardIssuer,
    #[error(
        "BROWSER_HOP1_OUTPUT_AUDIENCE must be an absolute HTTPS URL without a query or fragment"
    )]
    InvalidBrowserHop1OutputAudience,
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
        let browser_hop1 = BrowserHop1Config::from_env(workload.is_some())?;
        Ok(Self {
            issuer_url,
            github_exchange_audience: required("GITHUB_EXCHANGE_AUDIENCE")?,
            output_audience,
            policy_file: PathBuf::from(required("POLICY_FILE")?),
            keyring_file: PathBuf::from(required("KEYRING_FILE")?),
            replay_lease_namespace: required("REPLAY_LEASE_NAMESPACE")?,
            listen_address,
            token_ttl: Duration::from_secs(120),
            workload,
            browser_hop1,
        })
    }
}

impl BrowserHop1Config {
    fn from_env(workload_enabled: bool) -> Result<Option<Self>, ConfigError> {
        let enabled = match env::var("BROWSER_HOP1_ENABLED").as_deref() {
            Ok("true") => true,
            Ok("false") | Err(env::VarError::NotPresent) => false,
            Ok(_) | Err(env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::InvalidBrowserHop1Enabled);
            }
        };
        if !enabled {
            return Ok(None);
        }
        if !workload_enabled {
            return Err(ConfigError::BrowserHop1RequiresWorkload);
        }
        let steward_issuer = required("BROWSER_HOP1_STEWARD_ISSUER")?
            .trim_end_matches('/')
            .to_owned();
        if !valid_https_url(&steward_issuer) {
            return Err(ConfigError::InvalidBrowserHop1StewardIssuer);
        }
        let output_audience = required("BROWSER_HOP1_OUTPUT_AUDIENCE")?;
        if !valid_https_url(&output_audience) {
            return Err(ConfigError::InvalidBrowserHop1OutputAudience);
        }
        Ok(Some(Self {
            steward_issuer,
            assertion_audience: required("BROWSER_HOP1_ASSERTION_AUDIENCE")?,
            steward_jwks_file: PathBuf::from(required("BROWSER_HOP1_STEWARD_JWKS_FILE")?),
            output_audience,
        }))
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

fn valid_https_url(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|parsed| {
        parsed.scheme() == "https"
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none()
    })
}
