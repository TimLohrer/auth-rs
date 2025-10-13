use crate::{
    db::{get_main_db, AuthRsDatabase},
    SETTINGS_ID,
};
use anyhow::Result;
use mongodb::bson::{doc, DateTime, Uuid};
use rocket::serde::{Deserialize, Serialize};
use rocket_db_pools::{mongodb::Collection, Connection};
use thiserror::Error;
use dotenv::var;

use super::http_response::HttpResponse;

#[derive(Error, Debug)]
#[allow(unused)]
pub enum SettingsError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),
}

#[allow(unused)]
impl SettingsError {
    // Add a message method to maintain compatibility with existing code
    pub fn message(&self) -> String {
        match self {
            SettingsError::Unauthorized(msg) => format!("Unauthorized: {}", msg),
            SettingsError::Forbidden(msg) => format!("Forbidden: {}", msg),
            SettingsError::DatabaseError(msg) => format!("Database error: {}", msg),
            SettingsError::InternalServerError(msg) => format!("Internal server error: {}", msg),
        }
    }
}

// Implement conversion from SettingsError to HttpResponse
impl<T> From<SettingsError> for HttpResponse<T> {
    fn from(error: SettingsError) -> Self {
        match error {
            SettingsError::Unauthorized(msg) => HttpResponse {
                status: 401,
                message: format!("Unauthorized: {}", msg),
                data: None,
            },
            SettingsError::Forbidden(msg) => HttpResponse {
                status: 403,
                message: format!("Forbidden: {}", msg),
                data: None,
            },
            SettingsError::DatabaseError(msg) => HttpResponse {
                status: 500,
                message: format!("Database error: {}", msg),
                data: None,
            },
            SettingsError::InternalServerError(msg) => HttpResponse {
                status: 500,
                message: format!("Internal server error: {}", msg),
                data: None,
            },
        }
    }
}

// Implement conversion from AppError to SettingsError
use crate::errors::AppError;

impl From<AppError> for SettingsError {
    fn from(error: AppError) -> Self {
        match error {
            AppError::MissingPermissions => {
                SettingsError::Forbidden("Missing permissions".to_string())
            }
            AppError::RocketMongoError(err) => SettingsError::DatabaseError(err.to_string()),
            AppError::InternalServerError(msg) => SettingsError::InternalServerError(msg),
            _ => SettingsError::InternalServerError("Unexpected error".to_string()),
        }
    }
}

// Define a Result type alias for role operations
pub type SettingsResult<T> = Result<T, SettingsError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    #[serde(rename = "_id")]
    pub id: Uuid,
    pub version: String,
    pub version_history: Vec<(String, DateTime)>,
    pub open_registration: bool,
    pub allow_oauth_apps_for_users: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct SettingsDTO {
    pub id: Uuid,
    pub version: String,
    pub version_history: Vec<(String, i64)>,
    pub open_registration: bool,
    pub allow_oauth_apps_for_users: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            id: *SETTINGS_ID,
            version: var("VERSION").unwrap_or_else(|_| "1.0.22".to_string()),
            version_history: vec![("1.0.22".to_string(), DateTime::now())],
            open_registration: true,
            allow_oauth_apps_for_users: true,
        }
    }
}

impl Settings {
    pub const COLLECTION_NAME: &'static str = "settings";

    pub async fn initialize(db: &Collection<Settings>) -> SettingsResult<()> {
        let settings = Settings::default();

        match db.insert_one(settings.clone(), None).await {
            Ok(_) => Ok(()),
            Err(err) => Err(SettingsError::DatabaseError(format!(
                "Error initializing settings: {:?}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub fn to_dto(&self) -> SettingsDTO {
        SettingsDTO {
            id: self.id,
            version: self.version.clone(),
            version_history: self
                .version_history
                .iter()
                .map(|(ver, dt)| (ver.clone(), dt.timestamp_millis()))
                .collect(),
            open_registration: self.open_registration,
            allow_oauth_apps_for_users: self.allow_oauth_apps_for_users,
        }
    }

    #[allow(unused)]
    pub async fn get(connection: &Connection<AuthRsDatabase>) -> SettingsResult<Settings> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": *SETTINGS_ID
        };

        match db.find_one(filter, None).await {
            Ok(Some(settings)) => Ok(settings),
            Ok(None) => Err(SettingsError::DatabaseError(
                "Settings not found! -> Restart the backend to initialize them!".to_string(),
            )),
            Err(err) => Err(SettingsError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn update(
        &self,
        connection: &Connection<AuthRsDatabase>,
    ) -> SettingsResult<Settings> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": self.id
        };
        match db.replace_one(filter, self.clone(), None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(SettingsError::DatabaseError(format!(
                "Error updating settings: {:?}",
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
