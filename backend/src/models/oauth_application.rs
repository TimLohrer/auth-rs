use crate::db::{get_main_db, AuthRsDatabase};
use anyhow::Result;
use mongodb::bson::{doc, DateTime, Document, Uuid};
use rand::Rng;
use rocket::{
    futures::StreamExt,
    serde::{Deserialize, Serialize},
};
use rocket_db_pools::{mongodb::Collection, Connection};
use thiserror::Error;

use super::http_response::HttpResponse;

#[derive(Error, Debug)]
pub enum OAuthApplicationError {
    #[error("OAuth Application not found: {0}")]
    NotFound(Uuid),

    #[error("Invalid OAuth Application data: {0}")]
    InvalidData(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),
}

// Implement conversion from OAuthApplicationError to HttpResponse
impl<T> From<OAuthApplicationError> for HttpResponse<T> {
    fn from(error: OAuthApplicationError) -> Self {
        match error {
            OAuthApplicationError::NotFound(id) => HttpResponse {
                status: 404,
                message: format!("OAuth Application with ID {} not found", id),
                data: None,
            },
            OAuthApplicationError::InvalidData(msg) => HttpResponse {
                status: 400,
                message: format!("Invalid OAuth Application data: {}", msg),
                data: None,
            },
            OAuthApplicationError::DatabaseError(msg) => HttpResponse {
                status: 500,
                message: format!("Database error: {}", msg),
                data: None,
            },
            OAuthApplicationError::InternalServerError(msg) => HttpResponse {
                status: 500,
                message: format!("Internal server error: {}", msg),
                data: None,
            },
        }
    }
}

// Implement conversion from AppError to OAuthApplicationError
use crate::errors::AppError;

impl From<AppError> for OAuthApplicationError {
    fn from(error: AppError) -> Self {
        match error {
            AppError::DatabaseError(msg) => OAuthApplicationError::DatabaseError(msg),
            AppError::MongoError(err) => OAuthApplicationError::DatabaseError(err.to_string()),
            AppError::RocketMongoError(err) => {
                OAuthApplicationError::DatabaseError(err.to_string())
            }
            AppError::InternalServerError(msg) => OAuthApplicationError::InternalServerError(msg),
            _ => OAuthApplicationError::InternalServerError("Unexpected error".to_string()),
        }
    }
}

// Define a Result type alias for OAuth application operations
pub type OAuthApplicationResult<T> = Result<T, OAuthApplicationError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct OAuthApplication {
    #[serde(rename = "_id")]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub redirect_uris: Vec<String>,
    pub secret: String,
    pub owner: Uuid,
    pub created_at: DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct OAuthApplicationDTO {
    #[serde(rename = "_id")]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub redirect_uris: Vec<String>,
    pub owner: Uuid,
    pub created_at: DateTime,
}

impl OAuthApplication {
    pub const COLLECTION_NAME: &'static str = "oauth-applications";

    fn generate_secret() -> String {
        rand::rng()
            .sample_iter(rand::distr::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect()
    }

    pub fn new(
        name: String,
        description: Option<String>,
        redirect_uris: Vec<String>,
        owner: Uuid,
    ) -> OAuthApplicationResult<Self> {
        Ok(Self {
            id: Uuid::new(),
            name,
            description,
            redirect_uris,
            secret: Self::generate_secret(),
            owner,
            created_at: DateTime::now(),
        })
    }

    pub fn to_dto(&self) -> OAuthApplicationDTO {
        OAuthApplicationDTO {
            id: self.id,
            name: self.name.clone(),
            description: self.description.clone(),
            redirect_uris: self.redirect_uris.clone(),
            owner: self.owner,
            created_at: self.created_at,
        }
    }

    // ONLY USE THIS INTERNALLY!
    #[allow(unused)]
    pub async fn get_full_by_id(
        id: Uuid,
        connection: &Connection<AuthRsDatabase>,
    ) -> OAuthApplicationResult<OAuthApplication> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": id
        };
        match db.find_one(filter, None).await {
            Ok(Some(oauth_application)) => Ok(oauth_application),
            Ok(None) => Err(OAuthApplicationError::NotFound(id)),
            Err(err) => Err(OAuthApplicationError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn get_by_id(
        id: Uuid,
        connection: &Connection<AuthRsDatabase>,
    ) -> OAuthApplicationResult<OAuthApplication> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": id
        };
        match db.find_one(filter, None).await {
            Ok(Some(oauth_application)) => Ok(oauth_application),
            Ok(None) => Err(OAuthApplicationError::NotFound(id)),
            Err(err) => Err(OAuthApplicationError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn get_all(
        connection: &Connection<AuthRsDatabase>,
        filter: Option<Document>,
    ) -> OAuthApplicationResult<Vec<OAuthApplication>> {
        let db = Self::get_collection(connection);

        match db.find(filter, None).await {
            Ok(cursor) => {
                let oauth_applications = cursor
                    .map(|doc| match doc {
                        Ok(app) => {
                            let oauth_application: OAuthApplication = app;
                            oauth_application
                        }
                        Err(err) => panic!("Error parsing document: {:?}", err),
                    })
                    .collect::<Vec<OAuthApplication>>()
                    .await;
                Ok(oauth_applications)
            }
            Err(err) => Err(OAuthApplicationError::DatabaseError(format!(
                "Error fetching OAuth Applications: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn insert(
        &self,
        connection: &Connection<AuthRsDatabase>,
    ) -> OAuthApplicationResult<OAuthApplication> {
        let db = Self::get_collection(connection);

        match db.insert_one(self.clone(), None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(OAuthApplicationError::DatabaseError(format!(
                "Error inserting OAuth Application: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn update(
        &self,
        connection: &Connection<AuthRsDatabase>,
    ) -> OAuthApplicationResult<OAuthApplication> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": self.id
        };
        match db.replace_one(filter, self.clone(), None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(OAuthApplicationError::DatabaseError(format!(
                "Error updating OAuth Application: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn delete(
        &self,
        connection: &Connection<AuthRsDatabase>,
    ) -> OAuthApplicationResult<OAuthApplication> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": self.id
        };
        match db.delete_one(filter, None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(OAuthApplicationError::DatabaseError(format!(
                "Error deleting OAuth Application: {:?}",
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
