use crate::models::http_response::HttpResponse;
use crate::models::oauth_application::OAuthApplicationError;
use crate::models::role::RoleError;
use crate::models::settings::SettingsError;
use crate::models::user_error::UserError;
use mongodb::bson::Uuid;
use rocket::serde;
use std::env::VarError;
use thiserror::Error;
use webauthn_rs::prelude::WebauthnError;

#[derive(Error, Debug)]
#[allow(unused)]
pub enum AppError {
    #[error("Invalid UUID: {0}")]
    InvalidUuid(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("MongoDB error: {0}")]
    MongoError(#[from] mongodb::error::Error),

    #[error("Rocket MongoDB error: {0}")]
    RocketMongoError(#[from] rocket_db_pools::mongodb::error::Error),

    #[error("User not found: {0}")]
    UserNotFound(Uuid),

    #[error("Role not found: {0}")]
    RoleNotFound(Uuid),

    #[error("Passkey(s) not found via id: {0}")]
    PasskeyNotFound(Uuid),

    #[error("Missing permissions")]
    MissingPermissions,

    #[error("Cannot modify system user")]
    SystemUserModification,

    #[error("Password hashing error")]
    PasswordHashingError,

    #[error("Only system admin can assign admin role")]
    AdminRoleAssignment,

    #[error("No updates applied")]
    NoUpdatesApplied,

    #[error("Internal server error: {0}")]
    InternalServerError(String),

    #[error("Environment variable error: {0}")]
    EnvVarError(#[from] VarError),

    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("MFA required")]
    MfaRequired,

    #[error("Invalid MFA code")]
    InvalidMfaCode,

    #[error("User is disabled")]
    UserDisabled,

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Invalid or missing fields: {0}")]
    InvalidOrMissingFields(String),

    #[error("HTTP response error: {0}")]
    HttpResponseError(String),

    #[error("Webauthn error")]
    WebauthnError,

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Invalid UUID")]
    InvalidUUID,

    #[error("JSON serialization error: {0}")]
    JsonSerializationError(#[from] serde_json::Error),

    #[error("Device Error")]
    DeviceError(String),
}

// Implement From<HttpResponse<T>> for AppError
impl<T> From<HttpResponse<T>> for AppError
where
    T: serde::Serialize,
{
    fn from(response: HttpResponse<T>) -> Self {
        AppError::HttpResponseError(format!(
            "HTTP error {}: {}",
            response.status, response.message
        ))
    }
}

impl<T> From<AppError> for HttpResponse<T> {
    fn from(error: AppError) -> Self {
        match error {
            AppError::InvalidUuid(msg) => HttpResponse {
                status: 400,
                message: format!("Invalid UUID: {}", msg),
                data: None,
            },
            AppError::DatabaseError(err) => HttpResponse {
                status: 500,
                message: format!("Database error: {}", err),
                data: None,
            },
            AppError::MongoError(err) => HttpResponse {
                status: 500,
                message: format!("MongoDB error: {}", err),
                data: None,
            },
            AppError::RocketMongoError(err) => HttpResponse {
                status: 500,
                message: format!("MongoDB error: {}", err),
                data: None,
            },
            AppError::UserNotFound(id) => HttpResponse {
                status: 404,
                message: format!("User with ID {} not found", id),
                data: None,
            },
            AppError::RoleNotFound(id) => HttpResponse {
                status: 400,
                message: format!("Role with ID {} does not exist", id),
                data: None,
            },
            AppError::PasskeyNotFound(id) => HttpResponse {
                status: 400,
                message: format!("Passkey with ID {} does not exist", id),
                data: None,
            },
            AppError::MissingPermissions => HttpResponse {
                status: 403,
                message: "Missing permissions!".to_string(),
                data: None,
            },
            AppError::SystemUserModification => HttpResponse {
                status: 403,
                message: "Cannot modify system user".to_string(),
                data: None,
            },
            AppError::PasswordHashingError => HttpResponse {
                status: 500,
                message: "Error during password hashing".to_string(),
                data: None,
            },
            AppError::AdminRoleAssignment => HttpResponse {
                status: 403,
                message: "Only system admin can assign admin role".to_string(),
                data: None,
            },
            AppError::NoUpdatesApplied => HttpResponse {
                status: 200,
                message: "No updates applied.".to_string(),
                data: None,
            },
            AppError::InternalServerError(msg) => HttpResponse {
                status: 500,
                message: format!("Internal server error: {}", msg),
                data: None,
            },
            AppError::EnvVarError(err) => HttpResponse {
                status: 500,
                message: format!("Environment variable error: {}", err),
                data: None,
            },
            AppError::AuthenticationError(msg) => HttpResponse {
                status: 401,
                message: format!("Authentication error: {}", msg),
                data: None,
            },
            AppError::InvalidToken => HttpResponse {
                status: 401,
                message: "Invalid token".to_string(),
                data: None,
            },
            AppError::TokenExpired => HttpResponse {
                status: 401,
                message: "Token expired".to_string(),
                data: None,
            },
            AppError::InvalidCredentials => HttpResponse {
                status: 401,
                message: "Invalid credentials".to_string(),
                data: None,
            },
            AppError::MfaRequired => HttpResponse {
                status: 401,
                message: "MFA required".to_string(),
                data: None,
            },
            AppError::InvalidMfaCode => HttpResponse {
                status: 401,
                message: "Invalid MFA code".to_string(),
                data: None,
            },
            AppError::UserDisabled => HttpResponse {
                status: 403,
                message: "User is disabled".to_string(),
                data: None,
            },
            AppError::ValidationError(msg) => HttpResponse {
                status: 400,
                message: format!("Validation error: {}", msg),
                data: None,
            },
            AppError::InvalidOrMissingFields(msg) => HttpResponse {
                status: 400,
                message: format!("Invalid or missing fields: {}", msg),
                data: None,
            },
            AppError::HttpResponseError(msg) => HttpResponse {
                status: 500,
                message: format!("HTTP error: {}", msg),
                data: None,
            },
            AppError::WebauthnError => HttpResponse {
                status: 400,
                message: "Passkey error".to_string(),
                data: None,
            },
            AppError::InvalidState(msg) => HttpResponse {
                status: 400,
                message: format!("Invalid state: {}", msg),
                data: None,
            },
            AppError::InvalidUUID => HttpResponse {
                status: 400,
                message: "Invalid UUID".to_string(),
                data: None,
            },
            AppError::JsonSerializationError(err) => HttpResponse {
                status: 500,
                message: format!("JSON serialization error: {}", err),
                data: None,
            },
            AppError::DeviceError(msg) => HttpResponse {
                status: 400,
                message: format!("Device error: {}", msg),
                data: None,
            },
        }
    }
}

// Result type alias for application
pub type AppResult<T> = Result<T, AppError>;

// Add this new error type for API-specific errors
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Internal server error: {0}")]
    InternalError(String),

    #[error("App error: {0}")]
    AppError(#[from] AppError),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Invalid UUID")]
    InvalidUUID,
}

// Implement conversion from ApiError to HttpResponse
impl<T> From<ApiError> for HttpResponse<T> {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::NotFound(msg) => HttpResponse::not_found(&msg),
            ApiError::BadRequest(msg) => HttpResponse::bad_request(&msg),
            ApiError::Unauthorized(msg) => HttpResponse::unauthorized(&msg),
            ApiError::Forbidden(msg) => HttpResponse::forbidden(&msg),
            ApiError::InternalError(msg) => HttpResponse::internal_error(&msg),
            ApiError::AppError(err) => err.into(),
            ApiError::InvalidState(msg) => HttpResponse {
                status: 400,
                message: format!("Invalid state: {}", msg),
                data: None,
            },
            ApiError::InvalidUUID => HttpResponse {
                status: 400,
                message: "Invalid UUID".to_string(),
                data: None,
            },
        }
    }
}

// Add a type alias for API results
pub type ApiResult<T> = Result<T, ApiError>;

// Implement conversion from UserError to AppError
impl From<UserError> for AppError {
    fn from(error: UserError) -> Self {
        match error {
            UserError::NotFound(id) => AppError::UserNotFound(id),
            UserError::EmailAlreadyExists(email) => {
                AppError::ValidationError(format!("User with email {} already exists", email))
            }
            UserError::InvalidUuid(msg) => AppError::InvalidUuid(msg),
            UserError::MissingPermissions => AppError::MissingPermissions,
            UserError::SystemUserModification => AppError::SystemUserModification,
            UserError::PasswordHashingError => AppError::PasswordHashingError,
            UserError::AdminRoleAssignment => AppError::AdminRoleAssignment,
            UserError::RoleNotFound(id) => AppError::RoleNotFound(id),
            UserError::UserDisabled => AppError::UserDisabled,
            UserError::NoUpdatesApplied => AppError::NoUpdatesApplied,
            UserError::DatabaseError(msg) => AppError::DatabaseError(msg),
            UserError::InternalServerError(msg) => AppError::InternalServerError(msg),
            UserError::InvalidEmail => {
                AppError::InvalidOrMissingFields("Invalid email".to_string())
            }
            UserError::FirstNameRequired => {
                AppError::InvalidOrMissingFields("First name required".to_string())
            }
            UserError::PasswordToShort => {
                AppError::InvalidOrMissingFields("Password too short".to_string())
            }
            UserError::RegistrationClosed => AppError::MissingPermissions,
            UserError::RegistrationCodeInvalid => {
                AppError::InvalidOrMissingFields("Registration code invalid".to_string())
            }
            UserError::MaxDevicesReached => {
                AppError::DeviceError("Maximum number of devices reached".to_string())
            }
        }
    }
}

impl From<OAuthApplicationError> for AppError {
    fn from(error: OAuthApplicationError) -> Self {
        match error {
            OAuthApplicationError::NotFound(id) => {
                AppError::InternalServerError(format!("OAuth Application with ID {} not found", id))
            }
            OAuthApplicationError::InvalidData(msg) => {
                AppError::ValidationError(format!("Invalid OAuth Application data: {}", msg))
            }
            OAuthApplicationError::DatabaseError(msg) => AppError::DatabaseError(msg),
            OAuthApplicationError::InternalServerError(msg) => AppError::InternalServerError(msg),
        }
    }
}

impl From<RoleError> for AppError {
    fn from(error: RoleError) -> Self {
        match error {
            RoleError::NotFound(id) => AppError::RoleNotFound(id),
            RoleError::NameNotFound(name) => {
                AppError::ValidationError(format!("Role with name {} not found", name))
            }
            RoleError::NameAlreadyExists(name) => {
                AppError::ValidationError(format!("Role with name {} already exists", name))
            }
            RoleError::SystemRoleModification => AppError::SystemUserModification,
            RoleError::DatabaseError(msg) => AppError::DatabaseError(msg),
            RoleError::InternalServerError(msg) => AppError::InternalServerError(msg),
        }
    }
}

// Add From<ApiError> implementations for domain-specific errors
impl From<ApiError> for RoleError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::NotFound(_) => RoleError::NotFound(Uuid::new()),
            ApiError::BadRequest(msg) => RoleError::DatabaseError(msg),
            ApiError::Forbidden(_) => RoleError::SystemRoleModification,
            ApiError::Unauthorized(_) => RoleError::SystemRoleModification,
            ApiError::InternalError(msg) => RoleError::InternalServerError(msg),
            ApiError::AppError(err) => err.into(),
            ApiError::InvalidState(msg) => RoleError::DatabaseError(msg),
            ApiError::InvalidUUID => RoleError::NotFound(Uuid::new()),
        }
    }
}

impl From<ApiError> for OAuthApplicationError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::NotFound(_) => OAuthApplicationError::NotFound(Uuid::new()),
            ApiError::BadRequest(msg) => OAuthApplicationError::InvalidData(msg),
            ApiError::Forbidden(msg) => OAuthApplicationError::InvalidData(msg),
            ApiError::Unauthorized(msg) => OAuthApplicationError::InvalidData(msg),
            ApiError::InternalError(msg) => OAuthApplicationError::InternalServerError(msg),
            ApiError::AppError(err) => err.into(),
            ApiError::InvalidState(msg) => OAuthApplicationError::InvalidData(msg),
            ApiError::InvalidUUID => OAuthApplicationError::NotFound(Uuid::new()),
        }
    }
}

// Add implementation for converting from a string to AppError for WebAuthnError
impl From<String> for AppError {
    fn from(error: String) -> Self {
        AppError::InternalServerError(error)
    }
}

// Now we can properly convert WebAuthnError to a string and then to AppError
impl From<WebauthnError> for ApiError {
    #[allow(unused)]
    fn from(error: WebauthnError) -> Self {
        ApiError::AppError(AppError::WebauthnError)
    }
}

// Add From<ApiError> implementations for domain-specific errors
impl From<ApiError> for SettingsError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::NotFound(_) => SettingsError::DatabaseError("Not found".to_string()),
            ApiError::BadRequest(msg) => SettingsError::DatabaseError(msg),
            ApiError::Forbidden(_) => SettingsError::Forbidden("Forbidden".to_string()),
            ApiError::Unauthorized(_) => SettingsError::Unauthorized("Unauthorized".to_string()),
            ApiError::InternalError(msg) => SettingsError::InternalServerError(msg),
            ApiError::AppError(err) => err.into(),
            ApiError::InvalidState(msg) => SettingsError::DatabaseError(msg),
            ApiError::InvalidUUID => SettingsError::DatabaseError("Invalid UUID".to_string()),
        }
    }
}
