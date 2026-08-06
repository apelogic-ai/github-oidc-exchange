use aws_sdk_dynamodb::{Client, error::ProvideErrorMetadata, types::AttributeValue};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(feature = "test-support")]
use chrono::Utc;
#[cfg(feature = "test-support")]
use std::{collections::HashMap, sync::Arc};
#[cfg(feature = "test-support")]
use tokio::sync::Mutex;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReplayError {
    #[error("assertion has already been exchanged")]
    Replayed,
    #[error("replay ledger is unavailable")]
    Unavailable,
}

pub trait ReplayLedger: Send + Sync {
    fn use_once(
        &self,
        jti: &str,
        expires_at: i64,
    ) -> impl std::future::Future<Output = Result<(), ReplayError>> + Send;
}

#[derive(Clone)]
pub struct DynamoReplayLedger {
    client: Client,
    table_name: String,
}

impl DynamoReplayLedger {
    pub fn new(client: Client, table_name: String) -> Self {
        Self { client, table_name }
    }
}

impl ReplayLedger for DynamoReplayLedger {
    async fn use_once(&self, jti: &str, expires_at: i64) -> Result<(), ReplayError> {
        let result = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .item("jti_hash", AttributeValue::S(hash_jti(jti)))
            .item(
                "expires_at",
                AttributeValue::N((expires_at + 300).to_string()),
            )
            .condition_expression("attribute_not_exists(jti_hash)")
            .send()
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .as_service_error()
                    .and_then(ProvideErrorMetadata::code)
                    == Some("ConditionalCheckFailedException") =>
            {
                Err(ReplayError::Replayed)
            }
            Err(_) => Err(ReplayError::Unavailable),
        }
    }
}

fn hash_jti(jti: &str) -> String {
    Sha256::digest(jti.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Clone, Default)]
#[cfg(feature = "test-support")]
#[doc = "In-memory replay ledger for contract tests only."]
pub struct MemoryReplayLedger {
    seen: Arc<Mutex<HashMap<String, i64>>>,
}

#[cfg(feature = "test-support")]
impl ReplayLedger for MemoryReplayLedger {
    async fn use_once(&self, jti: &str, expires_at: i64) -> Result<(), ReplayError> {
        let now = Utc::now().timestamp();
        let mut seen = self.seen.lock().await;
        seen.retain(|_, expiry| *expiry > now);
        if seen.contains_key(jti) {
            return Err(ReplayError::Replayed);
        }
        seen.insert(jti.to_owned(), expires_at);
        Ok(())
    }
}
