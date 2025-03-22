use rocket::serde::{Serialize, Serializer};
use std::convert::TryFrom;
use std::fmt::Display;

use rocket::serde::{de::Error, Deserialize, Deserializer};

#[derive(Debug, Clone, PartialEq)]
pub enum OAuthScope {
    Roles(ScopeActions),
    AuditLogs(ScopeActions),
    Users(ScopeActions),
    OAuthApplications(ScopeActions),
    Connections(ScopeActions),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ScopeActions {
    Create,
    Read,
    Update,
    Delete,
    All,
}

impl Display for ScopeActions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ScopeActions::Create => "create",
            ScopeActions::Read => "read",
            ScopeActions::Update => "update",
            ScopeActions::Delete => "delete",
            ScopeActions::All => "*",
        };
        write!(f, "{}", s)
    }
}

impl TryFrom<&str> for ScopeActions {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "create" => Ok(ScopeActions::Create),
            "read" => Ok(ScopeActions::Read),
            "update" => Ok(ScopeActions::Update),
            "delete" => Ok(ScopeActions::Delete),
            "*" => Ok(ScopeActions::All),
            _ => Err("Invalid scope action"),
        }
    }
}

impl Serialize for ScopeActions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match self {
            ScopeActions::Create => "create",
            ScopeActions::Read => "read",
            ScopeActions::Update => "update",
            ScopeActions::Delete => "delete",
            ScopeActions::All => "*",
        };
        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for ScopeActions {
    fn deserialize<D>(deserializer: D) -> Result<ScopeActions, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "create" => Ok(ScopeActions::Create),
            "read" => Ok(ScopeActions::Read),
            "update" => Ok(ScopeActions::Update),
            "delete" => Ok(ScopeActions::Delete),
            "*" => Ok(ScopeActions::All),
            _ => Err(Error::custom("Invalid scope action")),
        }
    }
}

impl Display for OAuthScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthScope::Roles(actions) => write!(f, "roles:{}", actions),
            OAuthScope::AuditLogs(actions) => write!(f, "audit_logs:{}", actions),
            OAuthScope::Users(actions) => write!(f, "user:{}", actions),
            OAuthScope::OAuthApplications(actions) => write!(f, "oauth_applications:{}", actions),
            OAuthScope::Connections(actions) => write!(f, "connections:{}", actions),
        }
    }
}

impl TryFrom<String> for OAuthScope {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid scope format");
        }
        let action = ScopeActions::try_from(parts[1]).map_err(|_| "Invalid scope action")?;
        match parts[0] {
            "roles" => Ok(OAuthScope::Roles(action)),
            "audit_logs" => Ok(OAuthScope::AuditLogs(action)),
            "user" => Ok(OAuthScope::Users(action)),
            "oauth_applications" => Ok(OAuthScope::OAuthApplications(action)),
            "connections" => Ok(OAuthScope::Connections(action)),
            _ => Err("Unknown scope type"),
        }
    }
}

impl Serialize for OAuthScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match self {
            OAuthScope::Roles(action) => format!("roles:{}", action),
            OAuthScope::AuditLogs(action) => format!("audit_logs:{}", action),
            OAuthScope::Users(action) => format!("user:{}", action),
            OAuthScope::OAuthApplications(action) => format!("oauth_applications:{}", action),
            OAuthScope::Connections(action) => format!("connections:{}", action),
        };
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for OAuthScope {
    fn deserialize<D>(deserializer: D) -> Result<OAuthScope, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(Error::custom("Invalid scope"));
        }

        let actions = match parts[1] {
            "create" => ScopeActions::Create,
            "read" => ScopeActions::Read,
            "update" => ScopeActions::Update,
            "delete" => ScopeActions::Delete,
            "*" => ScopeActions::All,
            _ => return Err(Error::custom("Invalid scope action")),
        };

        match parts[0] {
            "roles" => Ok(OAuthScope::Roles(actions)),
            "audit_logs" => Ok(OAuthScope::AuditLogs(actions)),
            "user" => Ok(OAuthScope::Users(actions)),
            "oauth_applications" => Ok(OAuthScope::OAuthApplications(actions)),
            "connections" => Ok(OAuthScope::Connections(actions)),
            _ => Err(Error::custom("Invalid scope")),
        }
    }
}
