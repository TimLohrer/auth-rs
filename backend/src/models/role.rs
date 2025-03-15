use crate::db::{get_main_db, AuthRsDatabase};
use anyhow::Result;
use mongodb::bson::{doc, DateTime, Document, Uuid};
use rocket::{
    futures::StreamExt,
    serde::{Deserialize, Serialize},
};
use rocket_db_pools::{mongodb::Collection, Connection};
use thiserror::Error;

use super::http_response::HttpResponse;

#[derive(Error, Debug)]
pub enum RoleError {
    #[error("Role not found: {0}")]
    NotFound(Uuid),

    #[error("Role with name {0} not found")]
    NameNotFound(String),

    #[error("Role with name {0} already exists")]
    NameAlreadyExists(String),

    #[error("Cannot modify system role")]
    SystemRoleModification,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),
}

impl RoleError {
    // Add a message method to maintain compatibility with existing code
    pub fn message(&self) -> String {
        match self {
            RoleError::NotFound(id) => format!("Role with ID {} not found", id),
            RoleError::NameNotFound(name) => format!("Role with name {} not found", name),
            RoleError::NameAlreadyExists(name) => format!("Role with name {} already exists", name),
            RoleError::SystemRoleModification => "Cannot modify system role".to_string(),
            RoleError::DatabaseError(msg) => format!("Database error: {}", msg),
            RoleError::InternalServerError(msg) => format!("Internal server error: {}", msg),
        }
    }
}

// Implement conversion from RoleError to HttpResponse
impl<T> From<RoleError> for HttpResponse<T> {
    fn from(error: RoleError) -> Self {
        match error {
            RoleError::NotFound(id) => HttpResponse {
                status: 404,
                message: format!("Role with ID {} not found", id),
                data: None,
            },
            RoleError::NameNotFound(name) => HttpResponse {
                status: 404,
                message: format!("Role with name {} not found", name),
                data: None,
            },
            RoleError::NameAlreadyExists(name) => HttpResponse {
                status: 400,
                message: format!("Role with name {} already exists", name),
                data: None,
            },
            RoleError::SystemRoleModification => HttpResponse {
                status: 403,
                message: "Cannot modify system role".to_string(),
                data: None,
            },
            RoleError::DatabaseError(msg) => HttpResponse {
                status: 500,
                message: format!("Database error: {}", msg),
                data: None,
            },
            RoleError::InternalServerError(msg) => HttpResponse {
                status: 500,
                message: format!("Internal server error: {}", msg),
                data: None,
            },
        }
    }
}

// Implement conversion from AppError to RoleError
use crate::errors::AppError;

impl From<AppError> for RoleError {
    fn from(error: AppError) -> Self {
        match error {
            AppError::RoleNotFound(id) => RoleError::NotFound(id),
            AppError::SystemUserModification => RoleError::SystemRoleModification,
            AppError::DatabaseError(msg) => RoleError::DatabaseError(msg),
            AppError::MongoError(err) => RoleError::DatabaseError(err.to_string()),
            AppError::RocketMongoError(err) => RoleError::DatabaseError(err.to_string()),
            AppError::InternalServerError(msg) => RoleError::InternalServerError(msg),
            _ => RoleError::InternalServerError("Unexpected error".to_string()),
        }
    }
}

// Define a Result type alias for role operations
pub type RoleResult<T> = Result<T, RoleError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct Role {
    #[serde(rename = "_id")]
    pub id: Uuid,
    pub name: String,
    pub system: bool,
    pub created_at: DateTime,
}

impl Role {
    pub const COLLECTION_NAME: &'static str = "roles";

    pub fn new(name: String) -> RoleResult<Self> {
        Ok(Self {
            id: Uuid::new(),
            name,
            system: false,
            created_at: DateTime::now(),
        })
    }

    pub fn new_system(id: Uuid, name: String) -> RoleResult<Self> {
        Ok(Self {
            id,
            name,
            system: true,
            created_at: DateTime::now(),
        })
    }

    #[allow(unused)]
    pub async fn get_by_id(id: Uuid, connection: &Connection<AuthRsDatabase>) -> RoleResult<Role> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": id
        };
        match db.find_one(filter, None).await {
            Ok(Some(role)) => Ok(role),
            Ok(None) => Err(RoleError::NotFound(id)),
            Err(err) => Err(RoleError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn get_by_name(
        name: &str,
        connection: &Connection<AuthRsDatabase>,
    ) -> RoleResult<Role> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "name": name
        };
        match db.find_one(filter, None).await {
            Ok(Some(role)) => Ok(role),
            Ok(None) => Err(RoleError::NameNotFound(name.to_string())),
            Err(err) => Err(RoleError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn get_all(
        connection: &Connection<AuthRsDatabase>,
        filter: Option<Document>,
    ) -> RoleResult<Vec<Role>> {
        let db = Self::get_collection(connection);

        match db.find(filter, None).await {
            Ok(cursor) => {
                let roles = cursor
                    .map(|doc| match doc {
                        Ok(role) => role,
                        Err(err) => panic!("Error parsing role document: {:?}", err),
                    })
                    .collect::<Vec<Role>>()
                    .await;
                Ok(roles)
            }
            Err(err) => Err(RoleError::DatabaseError(format!(
                "Error fetching roles: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn insert(&self, connection: &Connection<AuthRsDatabase>) -> RoleResult<Role> {
        let db = Self::get_collection(connection);

        match db.insert_one(self.clone(), None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(RoleError::DatabaseError(format!(
                "Error inserting role: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn update(&self, connection: &Connection<AuthRsDatabase>) -> RoleResult<Role> {
        let db = Self::get_collection(connection);

        // Check if this is a system role
        if self.system {
            return Err(RoleError::SystemRoleModification);
        }

        let filter = doc! {
            "_id": self.id
        };
        match db.replace_one(filter, self.clone(), None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(RoleError::DatabaseError(format!(
                "Error updating role: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn delete(&self, connection: &Connection<AuthRsDatabase>) -> RoleResult<Role> {
        let db = Self::get_collection(connection);

        // Check if this is a system role
        if self.system {
            return Err(RoleError::SystemRoleModification);
        }

        let filter = doc! {
            "_id": self.id
        };
        match db.delete_one(filter, None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(RoleError::DatabaseError(format!(
                "Error deleting role: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    fn get_collection(connection: &Connection<AuthRsDatabase>) -> Collection<Self> {
        let db = get_main_db(connection);
        db.collection(Self::COLLECTION_NAME)
    }
}
