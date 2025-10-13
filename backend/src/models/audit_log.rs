use crate::db::{get_logs_db, AuthRsDatabase};
use anyhow::Result;
use mongodb::bson::{doc, DateTime, Uuid};
use rocket::{
    futures::StreamExt,
    serde::{Deserialize, Serialize},
};
use rocket_db_pools::{mongodb::Collection, Connection};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

use super::http_response::HttpResponse;

// Define a custom error type for audit logs
#[derive(Debug, Error)]
pub enum AuditLogError {
    #[error("Invalid entity type: {0}")]
    InvalidEntityType(String),

    #[error("Audit log not found")]
    NotFound,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

// Implement conversion from AuditLogError to HttpResponse
impl<T> From<AuditLogError> for HttpResponse<T> {
    fn from(error: AuditLogError) -> Self {
        match error {
            AuditLogError::InvalidEntityType(msg) => HttpResponse::bad_request(&msg),
            AuditLogError::NotFound => HttpResponse::not_found("Audit log not found"),
            AuditLogError::DatabaseError(msg) => HttpResponse::internal_error(&msg),
            AuditLogError::InvalidInput(msg) => HttpResponse::bad_request(&msg),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct AuditLog {
    #[serde(rename = "_id")]
    pub id: Uuid,
    pub entity_id: String,
    pub entity_type: AuditLogEntityType,
    pub action: AuditLogAction,
    pub reason: String,
    pub author_id: Uuid,
    pub old_values: Option<HashMap<String, String>>,
    pub new_values: Option<HashMap<String, String>>,
    pub created_at: DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct AuditLogDTO {
    #[serde(rename = "_id")]
    pub id: Uuid,
    pub entity_id: String,
    pub entity_type: AuditLogEntityType,
    pub action: AuditLogAction,
    pub reason: String,
    pub author_id: Uuid,
    pub old_values: Option<HashMap<String, String>>,
    pub new_values: Option<HashMap<String, String>>,
    #[serde(with = "crate::utils::serde_unix_timestamp")]
    pub created_at: DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub enum AuditLogAction {
    Create,
    Update,
    Login,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub enum AuditLogEntityType {
    User,
    Role,
    OAuthApplication,
    Settings,
    RegistrationToken,
    Passkey,
    Unknown,
}

#[allow(unused)]
impl AuditLogEntityType {
    pub fn from_string(entity_type: &str) -> Result<Self, AuditLogError> {
        match entity_type.to_uppercase().as_str() {
            "USER" => Ok(AuditLogEntityType::User),
            "ROLE" => Ok(AuditLogEntityType::Role),
            "OAUTH_APPLICATION" => Ok(AuditLogEntityType::OAuthApplication),
            "SETTINGS" => Ok(AuditLogEntityType::Settings),
            _ => Err(AuditLogError::InvalidInput(format!(
                "Unknown entity type: {}",
                entity_type
            ))),
        }
    }
}

impl fmt::Display for AuditLogEntityType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuditLogEntityType::User => write!(f, "USER"),
            AuditLogEntityType::Role => write!(f, "ROLE"),
            AuditLogEntityType::OAuthApplication => write!(f, "OAUTH_APPLICATION"),
            AuditLogEntityType::Settings => write!(f, "SETTINGS"),
            AuditLogEntityType::RegistrationToken => write!(f, "REGISTRATION_TOKEN"),
            AuditLogEntityType::Passkey => write!(f, "PASSKEY"),
            AuditLogEntityType::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

impl AuditLog {
    pub const COLLECTION_NAME_USERS: &'static str = "user-logs";
    pub const COLLECTION_NAME_ROLES: &'static str = "role-logs";
    pub const COLLECTION_NAME_OAUTH_APPLICATIONS: &'static str = "oauth-application-logs";
    pub const COLLECTION_NAME_REGISTRATION_TOKENS: &'static str = "registration-token-logs";
    pub const COLLECTION_NAME_PASSKEYS: &'static str = "passkey-logs";
    pub const COLLECTION_NAME_SYSTEM: &'static str = "system-logs";

    #[allow(unused)]
    pub fn new(
        entity_id: String,
        entity_type: AuditLogEntityType,
        action: AuditLogAction,
        reason: String,
        author_id: Uuid,
        old_values: Option<HashMap<String, String>>,
        new_values: Option<HashMap<String, String>>,
    ) -> Self {
        Self {
            id: Uuid::new(),
            entity_id,
            entity_type,
            action,
            reason,
            author_id,
            old_values,
            new_values,
            created_at: DateTime::now(),
        }
    }

    pub fn to_dto(&self) -> AuditLogDTO {
        AuditLogDTO {
            id: self.id,
            entity_id: self.entity_id.clone(),
            entity_type: self.entity_type.clone(),
            action: self.action.clone(),
            reason: self.reason.clone(),
            author_id: self.author_id,
            old_values: self.old_values.clone(),
            new_values: self.new_values.clone(),
            created_at: self.created_at,
        }
    }

    #[allow(unused)]
    pub async fn get_by_id(
        id: Uuid,
        entity_type: AuditLogEntityType,
        connection: &Connection<AuthRsDatabase>,
    ) -> Result<Self, AuditLogError> {
        let db = match Self::get_collection(&entity_type, connection) {
            Some(db) => db,
            None => {
                return Err(AuditLogError::InvalidEntityType(format!(
                    "Invalid entity type: {:?}",
                    entity_type
                )))
            }
        };

        let filter = doc! {
            "_id": id
        };
        match db.find_one(filter, None).await {
            Ok(Some(audit_log)) => Ok(audit_log),
            Ok(None) => Err(AuditLogError::NotFound),
            Err(err) => Err(AuditLogError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn get_by_entity_id(
        entity_id: Uuid,
        entity_type: AuditLogEntityType,
        connection: &Connection<AuthRsDatabase>,
    ) -> Result<Vec<Self>, AuditLogError> {
        let db = match Self::get_collection(&entity_type, connection) {
            Some(db) => db,
            None => {
                return Err(AuditLogError::InvalidEntityType(format!(
                    "Invalid entity type: {:?}",
                    entity_type
                )))
            }
        };

        let filter = doc! {
            "entityId": entity_id
        };
        match db.find(filter, None).await {
            Ok(cursor) => {
                let mut audit_logs = Vec::new();
                let mut stream = cursor;

                while let Some(result) = stream.next().await {
                    match result {
                        Ok(doc) => audit_logs.push(doc),
                        Err(err) => return Err(AuditLogError::DatabaseError(err.to_string())),
                    }
                }

                Ok(audit_logs)
            }
            Err(err) => Err(AuditLogError::DatabaseError(format!(
                "Error fetching audit logs: {}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn get_by_user_id(
        author_id: Option<Uuid>,
        connection: &Connection<AuthRsDatabase>,
    ) -> Result<Vec<Self>, AuditLogError> {
        let mut all_logs = vec![];

        // Get collections for each entity type
        let user_logs_collection = match Self::get_collection(&AuditLogEntityType::User, connection)
        {
            Some(coll) => coll,
            None => {
                return Err(AuditLogError::InvalidEntityType(
                    "User entity type invalid".to_string(),
                ))
            }
        };

        let role_logs_collection = match Self::get_collection(&AuditLogEntityType::Role, connection)
        {
            Some(coll) => coll,
            None => {
                return Err(AuditLogError::InvalidEntityType(
                    "Role entity type invalid".to_string(),
                ))
            }
        };

        let oauth_application_logs_collection =
            match Self::get_collection(&AuditLogEntityType::OAuthApplication, connection) {
                Some(coll) => coll,
                None => {
                    return Err(AuditLogError::InvalidEntityType(
                        "OAuth Application entity type invalid".to_string(),
                    ))
                }
            };

        let registration_token_logs_collection =
            match Self::get_collection(&AuditLogEntityType::RegistrationToken, connection) {
                Some(coll) => coll,
                None => {
                    return Err(AuditLogError::InvalidEntityType(
                        "Registration Token entity type invalid".to_string(),
                    ))
                }
            };

        let passkey_logs_collection =
            match Self::get_collection(&AuditLogEntityType::Passkey, connection) {
                Some(coll) => coll,
                None => {
                    return Err(AuditLogError::InvalidEntityType(
                        "Passkey entity type invalid".to_string(),
                    ))
                }
            };

        let system_ = match Self::get_collection(&AuditLogEntityType::Settings, connection) {
            Some(coll) => coll,
            None => {
                return Err(AuditLogError::InvalidEntityType(
                    "System entity type invalid".to_string(),
                ))
            }
        };
        
        let filter = if author_id.is_some() {
            Some(doc! {
                "$or": [
                    { "authorId": author_id.as_ref().unwrap().to_string() },
                    { "entityType": "User", "entityId": author_id.unwrap().to_string() }
                ]
            })
        } else {
            None
        };

        // Fetch user logs
        let user_logs = match user_logs_collection.find(filter.clone(), None).await {
            Ok(cursor) => {
                let mut logs = Vec::new();
                let mut stream = cursor;

                while let Some(result) = stream.next().await {
                    match result {
                        Ok(doc) => logs.push(doc),
                        Err(err) => return Err(AuditLogError::DatabaseError(err.to_string())),
                    }
                }


                logs
            }
            Err(err) => {
                return Err(AuditLogError::DatabaseError(format!(
                    "Error fetching user audit logs: {}",
                    err
                )))
            }
        };

        // Fetch role logs
        let role_logs = match role_logs_collection.find(filter.clone(), None).await {
            Ok(cursor) => {
                let mut logs = Vec::new();
                let mut stream = cursor;

                while let Some(result) = stream.next().await {
                    match result {
                        Ok(doc) => logs.push(doc),
                        Err(err) => return Err(AuditLogError::DatabaseError(err.to_string())),
                    }
                }

                logs
            }
            Err(err) => {
                return Err(AuditLogError::DatabaseError(format!(
                    "Error fetching role audit logs: {}",
                    err
                )))
            }
        };

        // Fetch OAuth application logs
        let oauth_application_logs = match oauth_application_logs_collection
            .find(filter.clone(), None)
            .await
        {
            Ok(cursor) => {
                let mut logs = Vec::new();
                let mut stream = cursor;

                while let Some(result) = stream.next().await {
                    match result {
                        Ok(doc) => logs.push(doc),
                        Err(err) => return Err(AuditLogError::DatabaseError(err.to_string())),
                    }
                }

                logs
            }
            Err(err) => {
                return Err(AuditLogError::DatabaseError(format!(
                    "Error fetching oauth application audit logs: {}",
                    err
                )))
            }
        };

        // Fetch registration token logs
        let registration_token_logs = match registration_token_logs_collection
            .find(filter.clone(), None)
            .await
        {
            Ok(cursor) => {
                let mut logs = Vec::new();
                let mut stream = cursor;

                while let Some(result) = stream.next().await {
                    match result {
                        Ok(doc) => logs.push(doc),
                        Err(err) => return Err(AuditLogError::DatabaseError(err.to_string())),
                    }
                }

                logs
            }
            Err(err) => {
                return Err(AuditLogError::DatabaseError(format!(
                    "Error fetching registration token audit logs: {}",
                    err
                )))
            }
        };

        // Fetch passkey logs
        let passkey_logs = match passkey_logs_collection.find(filter.clone(), None).await {
            Ok(cursor) => {
                let mut logs = Vec::new();
                let mut stream = cursor;

                while let Some(result) = stream.next().await {
                    match result {
                        Ok(doc) => logs.push(doc),
                        Err(err) => return Err(AuditLogError::DatabaseError(err.to_string())),
                    }
                }

                logs
            }
            Err(err) => {
                return Err(AuditLogError::DatabaseError(format!(
                    "Error fetching passkey audit logs: {}",
                    err
                )))
            }
        };

        // Fetch system logs
        let system_logs = match system_.find(filter.clone(), None).await {
            Ok(cursor) => {
                let mut logs = Vec::new();
                let mut stream = cursor;

                while let Some(result) = stream.next().await {
                    match result {
                        Ok(doc) => logs.push(doc),
                        Err(err) => return Err(AuditLogError::DatabaseError(err.to_string())),
                    }
                }

                logs
            }
            Err(err) => {
                return Err(AuditLogError::DatabaseError(format!(
                    "Error fetching system audit logs: {}",
                    err
                )))
            }
        };

        all_logs.extend(user_logs);
        all_logs.extend(role_logs);
        all_logs.extend(oauth_application_logs);
        all_logs.extend(registration_token_logs);
        all_logs.extend(passkey_logs);
        all_logs.extend(system_logs);

        all_logs.sort_by(|a, b| a.created_at.cmp(&b.created_at));

        Ok(all_logs)
    }

    #[allow(unused)]
    pub async fn get_all_from_type(
        entity_type: AuditLogEntityType,
        connection: &Connection<AuthRsDatabase>,
    ) -> Result<Vec<Self>, AuditLogError> {
        let db = match Self::get_collection(&entity_type, connection) {
            Some(db) => db,
            None => {
                return Err(AuditLogError::InvalidEntityType(format!(
                    "Invalid entity type: {:?}",
                    entity_type
                )))
            }
        };

        match db.find(None, None).await {
            Ok(cursor) => {
                let mut audit_logs = Vec::new();
                let mut stream = cursor;

                while let Some(result) = stream.next().await {
                    match result {
                        Ok(doc) => audit_logs.push(doc),
                        Err(err) => return Err(AuditLogError::DatabaseError(err.to_string())),
                    }
                }

                Ok(audit_logs)
            }
            Err(err) => Err(AuditLogError::DatabaseError(format!(
                "Error fetching audit logs: {}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn insert(
        &self,
        connection: &Connection<AuthRsDatabase>,
    ) -> Result<(), AuditLogError> {
        let db = match Self::get_collection(&self.entity_type, connection) {
            Some(db) => db,
            None => {
                return Err(AuditLogError::InvalidEntityType(format!(
                    "Invalid entity type: {:?}",
                    self.entity_type
                )))
            }
        };

        match db.insert_one(self.clone(), None).await {
            Ok(_) => Ok(()),
            Err(err) => Err(AuditLogError::DatabaseError(format!(
                "Error inserting audit log: {}",
                err
            ))),
        }
    }

    fn get_collection(
        entity_type: &AuditLogEntityType,
        connection: &Connection<AuthRsDatabase>,
    ) -> Option<Collection<AuditLog>> {
        let db = get_logs_db(connection);

        match *entity_type {
            AuditLogEntityType::User => Some(db.collection(Self::COLLECTION_NAME_USERS)),
            AuditLogEntityType::Role => Some(db.collection(Self::COLLECTION_NAME_ROLES)),
            AuditLogEntityType::OAuthApplication => {
                Some(db.collection(Self::COLLECTION_NAME_OAUTH_APPLICATIONS))
            }
            AuditLogEntityType::RegistrationToken => {
                Some(db.collection(Self::COLLECTION_NAME_REGISTRATION_TOKENS))
            }
            AuditLogEntityType::Passkey => Some(db.collection(Self::COLLECTION_NAME_PASSKEYS)),
            AuditLogEntityType::Settings => Some(db.collection(Self::COLLECTION_NAME_SYSTEM)),
            AuditLogEntityType::Unknown => None,
        }
    }
}
