use std::{
    collections::{HashMap, HashSet},
    fs::File,
    path::Path,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    IDENTITY_CONTRACT, POLICY_VERSION, SOURCE_AUTH_IDENTITY_CONTRACT, SOURCE_AUTH_POLICY_VERSION,
};

const SERVICE_PREFIX: &str = "agents.apelogic.ai/service-principal:";
const ACTING_PREFIX: &str = "agents.apelogic.ai/acting-user:";
const CANONICAL_USER_PREFIX: &str = "agents.apelogic.ai/canonical-user:";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: String,
    pub service_group: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acting_group_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_email_domains: Option<Vec<String>>,
    pub repositories: Vec<RepositoryPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actors: Option<HashMap<String, Actor>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPolicy {
    pub owner_id: String,
    pub repository_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refs: Option<Vec<String>>,
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
    pub actor_login: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub subject: String,
    pub groups: Option<Vec<String>>,
    pub identity_contract: &'static str,
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
        let value: serde_json::Value = serde_json::from_reader(file)
            .map_err(|error| PolicyError::Invalid(error.to_string()))?;
        let version = value.get("version").and_then(serde_json::Value::as_str);
        if !matches!(version, Some(POLICY_VERSION | SOURCE_AUTH_POLICY_VERSION)) {
            return Err(invalid("unsupported policy version"));
        }
        let policy: Self = serde_json::from_value(value)
            .map_err(|error| PolicyError::Invalid(error.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if !matches!(
            self.version.as_str(),
            POLICY_VERSION | SOURCE_AUTH_POLICY_VERSION
        ) {
            return Err(invalid("unsupported policy version"));
        }
        if !self.service_group.starts_with(SERVICE_PREFIX) || self.service_group == SERVICE_PREFIX {
            return Err(invalid(
                "service_group must use the Steward service-principal prefix",
            ));
        }
        if self.repositories.is_empty() {
            return Err(invalid("repositories must be non-empty"));
        }
        if self.version == POLICY_VERSION {
            self.validate_v5()
        } else {
            self.validate_v6()
        }
    }

    pub fn authorize(&self, claims: &crate::github::GitHubClaims) -> Result<Identity, PolicyError> {
        if self.version == POLICY_VERSION {
            self.authorize_v5(claims)
        } else if self.version == SOURCE_AUTH_POLICY_VERSION {
            self.authorize_v6(claims)
        } else {
            Err(PolicyError::Unauthorized)
        }
    }

    pub fn identity_contract(&self) -> &'static str {
        if self.version == SOURCE_AUTH_POLICY_VERSION {
            SOURCE_AUTH_IDENTITY_CONTRACT
        } else {
            IDENTITY_CONTRACT
        }
    }

    fn validate_v5(&self) -> Result<(), PolicyError> {
        let acting_group_prefix = self
            .acting_group_prefix
            .as_deref()
            .ok_or_else(|| invalid("acting_group_prefix is required by policy v5"))?;
        if acting_group_prefix != ACTING_PREFIX {
            return Err(invalid(
                "acting_group_prefix does not match the Steward contract",
            ));
        }
        let allowed_email_domains = self
            .allowed_email_domains
            .as_deref()
            .ok_or_else(|| invalid("allowed_email_domains is required by policy v5"))?;
        validate_domains(allowed_email_domains)?;
        let actors = self
            .actors
            .as_ref()
            .filter(|actors| !actors.is_empty())
            .ok_or_else(|| invalid("actors must be non-empty in policy v5"))?;
        validate_actors(actors, Some(allowed_email_domains), false)?;

        let mut repository_rules = HashSet::new();
        for repository in &self.repositories {
            validate_repository_ids(repository, false)?;
            let subjects = required_selector("subjects", &repository.subjects)?;
            let events = required_selector("events", &repository.events)?;
            let refs = required_selector("refs", &repository.refs)?;
            if !repository_rules.insert((
                repository.owner_id.as_str(),
                repository.repository_id.as_str(),
                subjects,
                events,
                refs,
            )) {
                return Err(invalid("duplicate repository authorization rule"));
            }
            validate_subjects(subjects)?;
        }
        Ok(())
    }

    fn validate_v6(&self) -> Result<(), PolicyError> {
        if self
            .acting_group_prefix
            .as_deref()
            .is_some_and(|prefix| prefix != ACTING_PREFIX)
        {
            return Err(invalid(
                "acting_group_prefix does not match the Steward contract",
            ));
        }
        if let Some(domains) = self.allowed_email_domains.as_deref() {
            validate_domains(domains)?;
        }
        match (
            self.actors.as_ref(),
            self.allowed_email_domains.as_deref(),
            self.acting_group_prefix.as_deref(),
        ) {
            (None, None, None) => {}
            (Some(actors), Some(domains), Some(ACTING_PREFIX)) => {
                if actors.is_empty() {
                    return Err(invalid("actors must be non-empty when configured"));
                }
                validate_actors(actors, Some(domains), true)?;
            }
            _ => {
                return Err(invalid(
                    "actors, allowed_email_domains, and acting_group_prefix must be configured together",
                ));
            }
        }

        let mut repository_ids = HashSet::new();
        for repository in &self.repositories {
            validate_repository_ids(repository, true)?;
            if !repository_ids.insert((
                repository.owner_id.as_str(),
                repository.repository_id.as_str(),
            )) {
                return Err(invalid("duplicate or ambiguous repository rule"));
            }
            if let Some(subjects) = repository.subjects.as_deref() {
                require_values("subjects", subjects)?;
                validate_subjects(subjects)?;
            }
            if let Some(events) = repository.events.as_deref() {
                require_values("events", events)?;
            }
            if let Some(refs) = repository.refs.as_deref() {
                require_values("refs", refs)?;
            }
        }
        Ok(())
    }

    fn authorize_v5(&self, claims: &crate::github::GitHubClaims) -> Result<Identity, PolicyError> {
        let actor = self
            .actors
            .as_ref()
            .and_then(|actors| actors.get(&claims.actor_id))
            .filter(|actor| actor.verified)
            .ok_or(PolicyError::Unauthorized)?;
        let mut matching_rules = self.repositories.iter().filter(|repository| {
            repository.owner_id == claims.repository_owner_id
                && repository.repository_id == claims.repository_id
                && selector_matches(&repository.subjects, &claims.sub)
                && selector_matches(&repository.events, &claims.event_name)
                && selector_matches(&repository.refs, &claims.git_ref)
        });
        let repository = matching_rules.next().ok_or(PolicyError::Unauthorized)?;
        if matching_rules.next().is_some() {
            return Err(PolicyError::Unauthorized);
        }
        let mut groups = vec![
            self.service_group.clone(),
            format!(
                "{}{}",
                self.acting_group_prefix
                    .as_deref()
                    .ok_or(PolicyError::Unauthorized)?,
                actor.email
            ),
            format!("{CANONICAL_USER_PREFIX}{}", actor.canonical_user_id),
        ];
        groups.sort();
        Ok(Identity {
            actor_id: claims.actor_id.clone(),
            actor_login: None,
            email: Some(actor.email.clone()),
            email_verified: Some(actor.verified),
            subject: format!("github-actions:actor:{}", claims.actor_id),
            groups: Some(groups),
            identity_contract: IDENTITY_CONTRACT,
            repository: format!("{}/{}", repository.owner_id, repository.repository_id),
            workflow_ref: claims.workflow_ref.clone(),
            job_workflow_ref: claims.job_workflow_ref.clone(),
        })
    }

    fn authorize_v6(&self, claims: &crate::github::GitHubClaims) -> Result<Identity, PolicyError> {
        if !numeric_identifier(&claims.actor_id) {
            return Err(PolicyError::Unauthorized);
        }
        let mut matching_rules = self.repositories.iter().filter(|repository| {
            repository.owner_id == claims.repository_owner_id
                && repository.repository_id == claims.repository_id
                && optional_selector_matches(&repository.subjects, &claims.sub)
                && optional_selector_matches(&repository.events, &claims.event_name)
                && optional_selector_matches(&repository.refs, &claims.git_ref)
        });
        let repository = matching_rules.next().ok_or(PolicyError::Unauthorized)?;
        if matching_rules.next().is_some() {
            return Err(PolicyError::Unauthorized);
        }

        let actor = match &self.actors {
            Some(actors) => Some(
                actors
                    .get(&claims.actor_id)
                    .filter(|actor| actor.verified)
                    .ok_or(PolicyError::Unauthorized)?,
            ),
            None => None,
        };
        let (email, email_verified, groups) = if let Some(actor) = actor {
            let acting_group_prefix = self
                .acting_group_prefix
                .as_deref()
                .ok_or(PolicyError::Unauthorized)?;
            let mut groups = vec![
                self.service_group.clone(),
                format!("{acting_group_prefix}{}", actor.email),
            ];
            groups.push(format!(
                "{CANONICAL_USER_PREFIX}{}",
                actor.canonical_user_id
            ));
            groups.sort();
            (Some(actor.email.clone()), Some(true), Some(groups))
        } else {
            (None, None, None)
        };
        Ok(Identity {
            actor_id: claims.actor_id.clone(),
            actor_login: Some(claims.actor.clone()),
            email,
            email_verified,
            subject: format!("github-actions:actor:{}", claims.actor_id),
            groups,
            identity_contract: SOURCE_AUTH_IDENTITY_CONTRACT,
            repository: format!("{}/{}", repository.owner_id, repository.repository_id),
            workflow_ref: claims.workflow_ref.clone(),
            job_workflow_ref: claims.job_workflow_ref.clone(),
        })
    }
}

fn required_selector<'a>(
    name: &str,
    selector: &'a Option<Vec<String>>,
) -> Result<&'a Vec<String>, PolicyError> {
    let values = selector
        .as_ref()
        .ok_or_else(|| invalid(&format!("{name} is required by policy v5")))?;
    require_values(name, values)?;
    Ok(values)
}

fn validate_repository_ids(
    repository: &RepositoryPolicy,
    bounded: bool,
) -> Result<(), PolicyError> {
    let valid = |value: &str| {
        if bounded {
            numeric_identifier(value)
        } else {
            decimal_identifier(value)
        }
    };
    if !valid(&repository.owner_id) || !valid(&repository.repository_id) {
        return Err(invalid("repository numeric IDs are required"));
    }
    Ok(())
}

fn validate_domains(domains: &[String]) -> Result<(), PolicyError> {
    require_values("allowed_email_domains", domains)?;
    if domains.iter().any(|domain| {
        domain.starts_with('.')
            || domain.ends_with('.')
            || !domain.contains('.')
            || domain != &domain.to_ascii_lowercase()
    }) {
        return Err(invalid(
            "allowed_email_domains must contain canonical DNS domain names",
        ));
    }
    Ok(())
}

fn validate_subjects(subjects: &[String]) -> Result<(), PolicyError> {
    if subjects.iter().any(|subject| {
        !subject.starts_with("repo:")
            || subject.len() > 2_048
            || !subject.bytes().all(|byte| byte.is_ascii_graphic())
    }) {
        return Err(invalid("subjects must be exact GitHub repo subjects"));
    }
    Ok(())
}

fn validate_actors(
    actors: &HashMap<String, Actor>,
    allowed_email_domains: Option<&[String]>,
    bounded_ids: bool,
) -> Result<(), PolicyError> {
    let mut canonical_user_ids = HashSet::new();
    for (actor_id, actor) in actors {
        let domain_allowed = allowed_email_domains.is_none_or(|domains| {
            domains
                .iter()
                .any(|domain| actor.email.ends_with(&format!("@{domain}")))
        });
        let actor_id_valid = if bounded_ids {
            numeric_identifier(actor_id)
        } else {
            decimal_identifier(actor_id)
        };
        if !actor_id_valid
            || !actor.verified
            || !canonical_email(&actor.email)
            || !canonical_user_id(&actor.canonical_user_id)
            || !domain_allowed
        {
            return Err(invalid(
                "actor mappings require a numeric ID, verified canonical email, and opaque canonical user ID",
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

fn selector_matches(selector: &Option<Vec<String>>, wanted: &str) -> bool {
    selector
        .as_ref()
        .is_some_and(|values| values.iter().any(|value| value == wanted))
}

fn optional_selector_matches(selector: &Option<Vec<String>>, wanted: &str) -> bool {
    selector
        .as_ref()
        .is_none_or(|values| values.iter().any(|value| value == wanted))
}

fn numeric_identifier(value: &str) -> bool {
    value.len() <= 20 && decimal_identifier(value) && value != "0" && !value.starts_with('0')
}

fn decimal_identifier(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
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
