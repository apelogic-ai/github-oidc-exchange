pub mod config;
pub mod github;
pub mod http;
pub mod keys;
pub mod policy;
pub mod replay;
pub mod service;

pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const POLICY_VERSION: &str = "github-oidc-exchange.apelogic.io/v2";
pub const KEYRING_VERSION: &str = "github-oidc-exchange.apelogic.io/keyring-v1";
pub const IDENTITY_CONTRACT: &str = "steward-task-v1";
