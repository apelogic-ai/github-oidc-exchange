use std::{collections::HashSet, fs::File, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::POLICY_VERSION;

const SERVICE_PREFIX: &str = "agents.apelogic.ai/service-principal:";
const ACTING_PREFIX: &str = "agents.apelogic.ai/acting-user:";
const CANONICAL_USER_PREFIX: &str = "agents.apelogic.ai/canonical-user:";
const BOOTSTRAP_PREFIX: &str = "agents.apelogic.ai/service-envelope-bootstrap:";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: String,
    pub service_group: String,
    pub acting_group_prefix: String,
    pub bootstrap_group: String,
    pub allowed_email_domains: Vec<String>,
    pub repositories: Vec<RepositoryPolicy>,
    pub actors: std::collections::HashMap<String, Actor>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPolicy {
    pub profile: IdentityProfile,
    pub owner_id: String,
    pub repository_id: String,
    pub subjects: Vec<String>,
    #[serde(default)]
    pub workflow_refs: Vec<String>,
    #[serde(default)]
    pub job_workflow_refs: Vec<String>,
    pub events: Vec<String>,
    pub refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityProfile {
    Task,
    Bootstrap,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub email: String,
    pub canonical_user_id: String,
    pub verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub actor_id: String,
    pub email: String,
    pub email_verified: bool,
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
        if !self.bootstrap_group.starts_with(BOOTSTRAP_PREFIX)
            || self.bootstrap_group == BOOTSTRAP_PREFIX
        {
            return Err(invalid(
                "bootstrap_group must use the Steward service-envelope-bootstrap prefix",
            ));
        }
        if self.bootstrap_group == self.service_group {
            return Err(invalid("task and bootstrap groups must be distinct"));
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
        let mut repository_rules = HashSet::new();
        for repository in &self.repositories {
            if repository.owner_id.is_empty() || repository.repository_id.is_empty() {
                return Err(invalid("repository numeric IDs are required"));
            }
            require_values("subjects", &repository.subjects)?;
            match repository.profile {
                IdentityProfile::Task => {
                    if !repository.workflow_refs.is_empty()
                        || !repository.job_workflow_refs.is_empty()
                    {
                        return Err(invalid(
                            "task rules derive authority from repository identity and must not select workflow paths",
                        ));
                    }
                }
                IdentityProfile::Bootstrap => {
                    require_values("workflow_refs", &repository.workflow_refs)?;
                    require_values("job_workflow_refs", &repository.job_workflow_refs)?;
                }
            }
            require_values("events", &repository.events)?;
            require_values("refs", &repository.refs)?;
            if !repository_rules.insert((
                &repository.owner_id,
                &repository.repository_id,
                &repository.subjects,
                &repository.workflow_refs,
                &repository.job_workflow_refs,
                &repository.events,
                &repository.refs,
            )) {
                return Err(invalid("duplicate repository authorization rule"));
            }
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
        let mut canonical_user_ids = HashSet::new();
        for (actor_id, actor) in &self.actors {
            if actor_id.is_empty()
                || !actor_id.chars().all(|character| character.is_ascii_digit())
                || !actor.verified
                || !canonical_email(&actor.email)
                || !canonical_user_id(&actor.canonical_user_id)
                || !self
                    .allowed_email_domains
                    .iter()
                    .any(|domain| actor.email.ends_with(&format!("@{domain}")))
            {
                return Err(invalid(
                    "actor mappings require a numeric ID, verified canonical corporate email, and opaque canonical user ID",
                ));
            }
            if !canonical_user_ids.insert(actor.canonical_user_id.as_str()) {
                return Err(invalid(
                    "canonical user IDs must be unique across actor mappings",
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
        let bootstrap_workflow = self.repositories.iter().any(|repository| {
            repository.profile == IdentityProfile::Bootstrap
                && contains(&repository.workflow_refs, &claims.workflow_ref)
                && contains(&repository.job_workflow_refs, &claims.job_workflow_ref)
        });
        let mut matching_rules = self.repositories.iter().filter(|repository| {
            repository.owner_id == claims.repository_owner_id
                && repository.repository_id == claims.repository_id
                && contains(&repository.subjects, &claims.sub)
                && match repository.profile {
                    IdentityProfile::Task => !bootstrap_workflow,
                    IdentityProfile::Bootstrap => {
                        contains(&repository.workflow_refs, &claims.workflow_ref)
                            && contains(&repository.job_workflow_refs, &claims.job_workflow_ref)
                    }
                }
                && contains(&repository.events, &claims.event_name)
                && contains(&repository.refs, &claims.git_ref)
        });
        let repository = matching_rules.next().ok_or(PolicyError::Unauthorized)?;
        if matching_rules.next().is_some() {
            return Err(PolicyError::Unauthorized);
        }
        let mut groups = match repository.profile {
            IdentityProfile::Task => vec![
                self.service_group.clone(),
                format!("{}{}", self.acting_group_prefix, actor.email),
                format!("{CANONICAL_USER_PREFIX}{}", actor.canonical_user_id),
            ],
            IdentityProfile::Bootstrap => vec![self.bootstrap_group.clone()],
        };
        groups.sort();
        Ok(Identity {
            actor_id: claims.actor_id.clone(),
            email: actor.email.clone(),
            email_verified: actor.verified,
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

fn canonical_user_id(value: &str) -> bool {
    value.strip_prefix("usr_").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn invalid(message: &str) -> PolicyError {
    PolicyError::Invalid(message.to_owned())
}
