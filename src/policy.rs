use std::{collections::HashSet, fs::File, path::Path};

use serde::Deserialize;
use thiserror::Error;

use crate::POLICY_VERSION;

const SERVICE_PREFIX: &str = "agents.apelogic.ai/service-principal:";
const ACTING_PREFIX: &str = "agents.apelogic.ai/acting-user:";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: String,
    pub service_group: String,
    pub acting_group_prefix: String,
    pub allowed_email_domains: Vec<String>,
    pub repositories: Vec<RepositoryPolicy>,
    pub actors: std::collections::HashMap<String, Actor>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPolicy {
    pub owner_id: String,
    pub repository_id: String,
    pub subjects: Vec<String>,
    pub workflow_refs: Vec<String>,
    pub job_workflow_refs: Vec<String>,
    pub events: Vec<String>,
    pub refs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub email: String,
    pub verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub actor_id: String,
    pub email: String,
    pub subject: String,
    pub groups: Vec<String>,
    pub repository: String,
    pub workflow_ref: String,
    pub job_workflow_ref: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("policy file is invalid: {0}")]
    Invalid(String),
    #[error("identity is not authorized")]
    Unauthorized,
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let file = File::open(path).map_err(|error| PolicyError::Invalid(error.to_string()))?;
        let policy: Self = serde_json::from_reader(file)
            .map_err(|error| PolicyError::Invalid(error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != POLICY_VERSION {
            return Err(invalid("unsupported policy version"));
        }
        if !self.service_group.starts_with(SERVICE_PREFIX) || self.service_group == SERVICE_PREFIX {
            return Err(invalid(
                "service_group must use the Steward service-principal prefix",
            ));
        }
        if self.acting_group_prefix != ACTING_PREFIX {
            return Err(invalid(
                "acting_group_prefix does not match the Steward contract",
            ));
        }
        if self.repositories.is_empty() || self.actors.is_empty() {
            return Err(invalid("repositories and actors must be non-empty"));
        }
        require_values("allowed_email_domains", &self.allowed_email_domains)?;
        if self.allowed_email_domains.iter().any(|domain| {
            domain.starts_with('.')
                || domain.ends_with('.')
                || !domain.contains('.')
                || domain != &domain.to_ascii_lowercase()
        }) {
            return Err(invalid(
                "allowed_email_domains must contain canonical DNS domain names",
            ));
        }
        let mut repositories = HashSet::new();
        for repository in &self.repositories {
            if repository.owner_id.is_empty() || repository.repository_id.is_empty() {
                return Err(invalid("repository numeric IDs are required"));
            }
            if !repositories.insert((&repository.owner_id, &repository.repository_id)) {
                return Err(invalid("duplicate repository policy"));
            }
            require_values("subjects", &repository.subjects)?;
            require_values("workflow_refs", &repository.workflow_refs)?;
            require_values("job_workflow_refs", &repository.job_workflow_refs)?;
            require_values("events", &repository.events)?;
            require_values("refs", &repository.refs)?;
            let owner_marker = format!("@{}/", repository.owner_id);
            let repository_marker = format!("@{}:", repository.repository_id);
            if repository.subjects.iter().any(|subject| {
                !subject.starts_with("repo:")
                    || !subject.contains(&owner_marker)
                    || !subject.contains(&repository_marker)
            }) {
                return Err(invalid(
                    "subjects must contain immutable owner and repository IDs",
                ));
            }
        }
        for (actor_id, actor) in &self.actors {
            if actor_id.is_empty()
                || !actor_id.chars().all(|character| character.is_ascii_digit())
                || !actor.verified
                || !canonical_email(&actor.email)
                || !self
                    .allowed_email_domains
                    .iter()
                    .any(|domain| actor.email.ends_with(&format!("@{domain}")))
            {
                return Err(invalid(
                    "actor mappings require a numeric ID and verified canonical corporate email",
                ));
            }
        }
        Ok(())
    }

    pub fn authorize(&self, claims: &crate::github::GitHubClaims) -> Result<Identity, PolicyError> {
        let actor = self
            .actors
            .get(&claims.actor_id)
            .filter(|actor| actor.verified)
            .ok_or(PolicyError::Unauthorized)?;
        let repository = self
            .repositories
            .iter()
            .find(|repository| {
                repository.owner_id == claims.repository_owner_id
                    && repository.repository_id == claims.repository_id
            })
            .ok_or(PolicyError::Unauthorized)?;
        if !contains(&repository.subjects, &claims.sub)
            || !contains(&repository.workflow_refs, &claims.workflow_ref)
            || !contains(&repository.job_workflow_refs, &claims.job_workflow_ref)
            || !contains(&repository.events, &claims.event_name)
            || !contains(&repository.refs, &claims.git_ref)
        {
            return Err(PolicyError::Unauthorized);
        }
        let mut groups = vec![
            self.service_group.clone(),
            format!("{}{}", self.acting_group_prefix, actor.email),
        ];
        groups.sort();
        Ok(Identity {
            actor_id: claims.actor_id.clone(),
            email: actor.email.clone(),
            subject: format!("github-actions:actor:{}", claims.actor_id),
            groups,
            repository: format!("{}/{}", repository.owner_id, repository.repository_id),
            workflow_ref: claims.workflow_ref.clone(),
            job_workflow_ref: claims.job_workflow_ref.clone(),
        })
    }
}

fn require_values(name: &str, values: &[String]) -> Result<(), PolicyError> {
    let unique: HashSet<&str> = values.iter().map(String::as_str).collect();
    if values.is_empty()
        || unique.len() != values.len()
        || values.iter().any(|value| value.is_empty())
    {
        return Err(invalid(&format!(
            "{name} must contain unique non-empty values"
        )));
    }
    Ok(())
}

fn contains(values: &[String], wanted: &str) -> bool {
    values.iter().any(|value| value == wanted)
}

fn canonical_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && !value.contains(char::is_whitespace)
        && value == value.to_ascii_lowercase()
}

fn invalid(message: &str) -> PolicyError {
    PolicyError::Invalid(message.to_owned())
}
