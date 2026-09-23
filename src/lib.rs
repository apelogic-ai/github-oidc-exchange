pub mod browser_hop1;
pub mod config;
pub mod github;
pub mod http;
pub mod keys;
pub mod policy;
pub mod replay;
pub mod service;
pub mod workload;

pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const POLICY_VERSION: &str = "github-oidc-exchange.apelogic.io/v5";
pub const KEYRING_VERSION: &str = "github-oidc-exchange.apelogic.io/keyring-v1";
pub const RSA_KEYRING_VERSION: &str = "github-oidc-exchange.apelogic.io/rsa-keyring-v1";
pub const WORKLOAD_POLICY_VERSION: &str = "github-oidc-exchange.apelogic.io/workload-policy-v1";
pub const IDENTITY_CONTRACT: &str = "steward-task-v2";
pub const SOURCE_PROVENANCE_CONTRACT: &str = "steward.source-provenance/v1";
pub const WORKLOAD_IDENTITY_CONTRACT: &str = "openshell-workload-v1";
pub const IDENTITY_BROWSER_HOP1_CONTRACT: &str = "steward-browser-mcp-hop1-v1";
