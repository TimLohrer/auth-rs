use crate::{
    db::{get_main_db, AuthRsDatabase},
    errors::ApiError,
};
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
pub enum RegistrationTokenError {
    #[error("Registration token not found: {0}")]
    NotFound(Uuid),

    #[error("Role not found: {0}")]
    RoleNotFound(Uuid),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),
}

// Implement conversion from RegistrationTokenError to HttpResponse
impl<T> From<RegistrationTokenError> for HttpResponse<T> {
    fn from(error: RegistrationTokenError) -> Self {
        match error {
            RegistrationTokenError::NotFound(id) => HttpResponse {
                status: 404,
                message: format!("Registration token with ID {} not found", id),
                data: None,
            },
            RegistrationTokenError::RoleNotFound(id) => HttpResponse {
                status: 404,
                message: format!("Role with ID {} not found", id),
                data: None,
            },
            RegistrationTokenError::DatabaseError(msg) => HttpResponse {
                status: 500,
                message: format!("Database error: {}", msg),
                data: None,
            },
            RegistrationTokenError::Forbidden(msg) => HttpResponse {
                status: 403,
                message: format!("Forbidden: {}", msg),
                data: None,
            },
            RegistrationTokenError::InternalServerError(msg) => HttpResponse {
                status: 500,
                message: format!("Internal server error: {}", msg),
                data: None,
            },
        }
    }
}

// Implement conversion from AppError to RegistrationTokenError
use crate::errors::AppError;

impl From<AppError> for RegistrationTokenError {
    fn from(error: AppError) -> Self {
        match error {
            AppError::DatabaseError(msg) => RegistrationTokenError::DatabaseError(msg),
            AppError::MongoError(err) => RegistrationTokenError::DatabaseError(err.to_string()),
            AppError::RocketMongoError(err) => {
                RegistrationTokenError::DatabaseError(err.to_string())
            }
            AppError::InternalServerError(msg) => RegistrationTokenError::InternalServerError(msg),
            _ => RegistrationTokenError::InternalServerError("Unexpected error".to_string()),
        }
    }
}

impl From<ApiError> for RegistrationTokenError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::Forbidden(msg) => RegistrationTokenError::Forbidden(msg),
            _ => RegistrationTokenError::InternalServerError("Unexpected error".to_string()),
        }
    }
}

// Define a Result type alias for OAuth application operations
pub type RegistrationTokenResult<T> = Result<T, RegistrationTokenError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct RegistrationToken {
    #[serde(rename = "_id")]
    pub id: Uuid,
    pub code: String,
    pub max_uses: u32,
    pub uses: Vec<Uuid>,
    pub expires_in: Option<u64>,
    pub auto_roles: Vec<Uuid>,
    pub expires_from: Option<DateTime>,
    pub created_at: DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTokenDTO {
    pub id: Uuid,
    pub code: String,
    pub max_uses: u32,
    pub uses: Vec<Uuid>,
    pub expires_in: Option<u64>,
    pub auto_roles: Vec<Uuid>,
    #[serde(with = "crate::utils::serde_unix_timestamp::option")]
    pub expires_from: Option<DateTime>,
    #[serde(with = "crate::utils::serde_unix_timestamp")]
    pub created_at: DateTime,
}

impl RegistrationToken {
    pub const COLLECTION_NAME: &'static str = "registration-tokens";

    fn generate_code() -> String {
        let mut rng = rand::rng();
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let code: String = (0..6)
            .map(|_| chars.chars().nth(rng.random_range(0..chars.len())).unwrap())
            .collect();
        code
    }

    #[allow(unused)]
    pub fn new(
        max_uses: Option<u32>,
        expires_in: Option<u64>,
        auto_roles: Option<Vec<Uuid>>,
    ) -> RegistrationTokenResult<Self> {
        Ok(Self {
            id: Uuid::new(),
            code: Self::generate_code(),
            max_uses: max_uses.unwrap_or(1),
            uses: vec![],
            expires_in,
            auto_roles: auto_roles.unwrap_or_default(),
            expires_from: if expires_in.is_some() {
                Some(DateTime::now())
            } else {
                None
            },
            created_at: DateTime::now(),
        })
    }

    pub fn to_dto(&self) -> RegistrationTokenDTO {
        RegistrationTokenDTO {
            id: self.id,
            code: self.code.clone(),
            max_uses: self.max_uses,
            uses: self.uses.clone(),
            expires_in: self.expires_in,
            auto_roles: self.auto_roles.clone(),
            expires_from: self.expires_from,
            created_at: self.created_at,
        }
    }

    #[allow(unused)]
    pub async fn get_by_id(
        id: Uuid,
        connection: &Connection<AuthRsDatabase>,
    ) -> RegistrationTokenResult<RegistrationToken> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": id
        };
        match db.find_one(filter, None).await {
            Ok(Some(registration_token)) => Ok(registration_token),
            Ok(None) => Err(RegistrationTokenError::NotFound(id)),
            Err(err) => Err(RegistrationTokenError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn get_all(
        connection: &Connection<AuthRsDatabase>,
        filter: Option<Document>,
    ) -> RegistrationTokenResult<Vec<RegistrationToken>> {
        let db = Self::get_collection(connection);

        match db.find(filter, None).await {
            Ok(cursor) => {
                let registration_tokens = cursor
                    .map(|doc| match doc {
                        Ok(app) => {
                            let registration_token: RegistrationToken = app;
                            registration_token
                        }
                        Err(err) => panic!("Error parsing document: {:?}", err),
                    })
                    .collect::<Vec<RegistrationToken>>()
                    .await;
                Ok(registration_tokens)
            }
            Err(err) => Err(RegistrationTokenError::DatabaseError(format!(
                "Error fetching Registration tokens: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn get_by_code(
        code: String,
        connection: &Connection<AuthRsDatabase>,
    ) -> RegistrationTokenResult<RegistrationToken> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "code": code
        };
        match db.find_one(filter, None).await {
            Ok(Some(registration_token)) => Ok(registration_token),
            Ok(None) => Err(RegistrationTokenError::NotFound(Uuid::new())),
            Err(err) => Err(RegistrationTokenError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn insert(
        &self,
        connection: &Connection<AuthRsDatabase>,
    ) -> RegistrationTokenResult<RegistrationToken> {
        let db = Self::get_collection(connection);

        match db.insert_one(self.clone(), None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(RegistrationTokenError::DatabaseError(format!(
                "Error inserting Registration token: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn update(
        &self,
        connection: &Connection<AuthRsDatabase>,
    ) -> RegistrationTokenResult<RegistrationToken> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": self.id
        };
        match db.replace_one(filter, self.clone(), None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(RegistrationTokenError::DatabaseError(format!(
                "Error updating Registration token: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn use_token(
        &self,
        connection: &Connection<AuthRsDatabase>,
        user_id: Uuid,
    ) -> RegistrationTokenResult<RegistrationToken> {
        let db = Self::get_collection(connection);

        if self.uses.len() >= self.max_uses as usize {
            return Err(RegistrationTokenError::Forbidden(
                "Registration token has reached its maximum number of uses".to_string(),
            ));
        } else if let Some(expires_in) = self.expires_in {
            if DateTime::now().timestamp_millis()
                > (self.expires_from.unwrap().timestamp_millis() + expires_in as i64)
            {
                return Err(RegistrationTokenError::Forbidden(
                    "Registration token has expired".to_string(),
                ));
            }
        }

        let filter = doc! {
            "_id": self.id
        };
        let update = doc! {
            "$addToSet": { "uses": user_id }
        };
        match db.update_one(filter, update, None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(RegistrationTokenError::DatabaseError(format!(
                "Error using Registration token: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn delete(
        &self,
        connection: &Connection<AuthRsDatabase>,
    ) -> RegistrationTokenResult<RegistrationToken> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": self.id
        };
        match db.delete_one(filter, None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(RegistrationTokenError::DatabaseError(format!(
                "Error deleting Registration token: {:?}",
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
