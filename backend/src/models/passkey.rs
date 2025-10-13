use super::http_response::HttpResponse;
use crate::db::{get_main_db, AuthRsDatabase};
use anyhow::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use mongodb::bson::{doc, DateTime, Document, Uuid};
use rocket::{
    futures::StreamExt,
    serde::{Deserialize, Serialize},
};
use rocket_db_pools::{mongodb::Collection, Connection};
use thiserror::Error;
use webauthn_rs::prelude::CredentialID;

#[derive(Error, Debug)]
#[allow(unused)]
pub enum PasskeyError {
    #[error("Passkey not found: {0}")]
    NotFound(String),

    #[error("Passkey with name {0} not found")]
    NameNotFound(String),

    #[error("Passkey with name {0} already exists")]
    NameAlreadyExists(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),
}

impl PasskeyError {
    // Add a message method to maintain compatibility with existing code
    #[allow(unused)]
    pub fn message(&self) -> String {
        match self {
            PasskeyError::NotFound(id) => format!("Passkey with ID {} not found", id),
            PasskeyError::NameNotFound(name) => format!("Passkey with name {} not found", name),
            PasskeyError::NameAlreadyExists(name) => {
                format!("Passkey with name {} already exists", name)
            }
            PasskeyError::DatabaseError(msg) => format!("Database error: {}", msg),
            PasskeyError::InternalServerError(msg) => format!("Internal server error: {}", msg),
        }
    }
}

// Implement conversion from PasskeyError to HttpResponse
impl<T> From<PasskeyError> for HttpResponse<T> {
    fn from(error: PasskeyError) -> Self {
        match error {
            PasskeyError::NotFound(id) => HttpResponse {
                status: 404,
                message: format!("Passkey with ID {} not found", id),
                data: None,
            },
            PasskeyError::NameNotFound(name) => HttpResponse {
                status: 404,
                message: format!("Passkey with name {} not found", name),
                data: None,
            },
            PasskeyError::NameAlreadyExists(name) => HttpResponse {
                status: 400,
                message: format!("Passkey with name {} already exists", name),
                data: None,
            },
            PasskeyError::DatabaseError(msg) => HttpResponse {
                status: 500,
                message: format!("Database error: {}", msg),
                data: None,
            },
            PasskeyError::InternalServerError(msg) => HttpResponse {
                status: 500,
                message: format!("Internal server error: {}", msg),
                data: None,
            },
        }
    }
}

// Implement conversion from AppError to PasskeyError
use crate::errors::AppError;

impl From<AppError> for PasskeyError {
    fn from(error: AppError) -> Self {
        match error {
            AppError::PasskeyNotFound(id) => PasskeyError::NotFound(id.to_string()),
            AppError::DatabaseError(msg) => PasskeyError::DatabaseError(msg),
            AppError::MongoError(err) => PasskeyError::DatabaseError(err.to_string()),
            AppError::RocketMongoError(err) => PasskeyError::DatabaseError(err.to_string()),
            AppError::InternalServerError(msg) => PasskeyError::InternalServerError(msg),
            _ => PasskeyError::InternalServerError("Unexpected error".to_string()),
        }
    }
}

// Define a Result type alias for passkey operations
pub type PasskeyResult<T> = Result<T, PasskeyError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct Passkey {
    #[serde(rename = "_id")]
    pub id: String,
    pub owner: Uuid,
    pub name: String,
    pub credential: webauthn_rs::prelude::Passkey,
    pub created_at: DateTime,
}

// DTO for API responses with less sensitive data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyDTO {
    pub id: String,
    pub owner: Uuid,
    pub name: String,
    #[serde(with = "crate::utils::serde_unix_timestamp")]
    pub created_at: DateTime,
}

impl Passkey {
    pub const COLLECTION_NAME: &'static str = "passkeys";

    pub fn new(
        cred_id: &CredentialID,
        name: String,
        owner: Uuid,
        passkey: webauthn_rs::prelude::Passkey,
    ) -> Self {
        Self {
            id: URL_SAFE_NO_PAD.encode(cred_id),
            owner,
            name,
            created_at: DateTime::now(),
            credential: passkey,
        }
    }

    // Convert to DTO
    pub fn to_dto(&self) -> PasskeyDTO {
        PasskeyDTO {
            id: self.id.clone(),
            owner: self.owner,
            name: self.name.clone(),
            created_at: self.created_at,
        }
    }

    #[allow(unused)]
    pub async fn get_by_id(
        id: &str,
        connection: &Connection<AuthRsDatabase>,
    ) -> PasskeyResult<Passkey> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": id
        };
        match db.find_one(filter, None).await {
            Ok(Some(passkey)) => Ok(passkey),
            Ok(None) => Err(PasskeyError::NotFound(id.to_string())),
            Err(err) => Err(PasskeyError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn get_by_owner(
        owner_id: Uuid,
        connection: &Connection<AuthRsDatabase>,
    ) -> PasskeyResult<Vec<Passkey>> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "owner": owner_id
        };
        match db.find(filter, None).await {
            Ok(cursor) => {
                let passkeys = cursor
                    .map(|doc| match doc {
                        Ok(passkey) => passkey,
                        Err(err) => panic!("Error parsing passkey document: {:?}", err),
                    })
                    .collect::<Vec<Passkey>>()
                    .await;
                Ok(passkeys)
            }
            Err(err) => Err(PasskeyError::DatabaseError(format!(
                "Error fetching passkeys: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn get_all(
        connection: &Connection<AuthRsDatabase>,
        filter: Option<Document>,
    ) -> PasskeyResult<Vec<Passkey>> {
        let db = Self::get_collection(connection);

        match db.find(filter, None).await {
            Ok(cursor) => {
                let passkeys = cursor
                    .map(|doc| match doc {
                        Ok(passkey) => passkey,
                        Err(err) => panic!("Error parsing passkey document: {:?}", err),
                    })
                    .collect::<Vec<Passkey>>()
                    .await;
                Ok(passkeys)
            }
            Err(err) => Err(PasskeyError::DatabaseError(format!(
                "Error fetching passkeys: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn insert(&self, connection: &Connection<AuthRsDatabase>) -> PasskeyResult<Passkey> {
        let db = Self::get_collection(connection);

        match db.insert_one(self.clone(), None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(PasskeyError::DatabaseError(format!(
                "Error inserting passkey: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn update(&self, connection: &Connection<AuthRsDatabase>) -> PasskeyResult<Passkey> {
        let db = Self::get_collection(connection);

        let id = self.id.clone();

        let filter = doc! {
            "_id": id
        };
        match db.replace_one(filter, self.clone(), None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(PasskeyError::DatabaseError(format!(
                "Error updating passkey: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn delete(&self, connection: &Connection<AuthRsDatabase>) -> PasskeyResult<Passkey> {
        let db = Self::get_collection(connection);

        let id = self.id.clone();

        let filter = doc! {
            "_id": id
        };
        match db.delete_one(filter, None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(PasskeyError::DatabaseError(format!(
                "Error deleting passkey: {:?}",
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
