use crate::models::http_response::HttpResponse;
use mongodb::bson::Uuid;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UserError {
    #[error("User not found: {0}")]
    NotFound(Uuid),

    #[error("User with email {0} already exists")]
    EmailAlreadyExists(String),

    #[error("Invalid UUID: {0}")]
    InvalidUuid(String),

    #[error("Missing permissions to perform this action")]
    MissingPermissions,

    #[error("Cannot modify system user")]
    SystemUserModification,

    #[error("Password hashing error: {0}")]
    PasswordHashingError(String),

    #[error("Only system admin can assign admin role")]
    AdminRoleAssignment,

    #[error("Role not found: {0}")]
    RoleNotFound(Uuid),

    #[error("User is disabled")]
    UserDisabled,

    #[error("No updates applied to user")]
    NoUpdatesApplied,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),
}

// Implement conversion from UserError to HttpResponse
impl<T> From<UserError> for HttpResponse<T> {
    fn from(error: UserError) -> Self {
        match error {
            UserError::NotFound(id) => HttpResponse {
                status: 404,
                message: format!("User with ID {} not found", id),
                data: None,
            },
            UserError::EmailAlreadyExists(email) => HttpResponse {
                status: 400,
                message: format!("User with email {} already exists", email),
                data: None,
            },
            UserError::InvalidUuid(msg) => HttpResponse {
                status: 400,
                message: format!("Invalid UUID: {}", msg),
                data: None,
            },
            UserError::MissingPermissions => HttpResponse {
                status: 403,
                message: "Missing permissions to perform this action".to_string(),
                data: None,
            },
            UserError::SystemUserModification => HttpResponse {
                status: 403,
                message: "Cannot modify system user".to_string(),
                data: None,
            },
            UserError::PasswordHashingError(msg) => HttpResponse {
                status: 500,
                message: format!("Failed to hash password: {}", msg),
                data: None,
            },
            UserError::AdminRoleAssignment => HttpResponse {
                status: 403,
                message: "Only system admin can assign admin role".to_string(),
                data: None,
            },
            UserError::RoleNotFound(id) => HttpResponse {
                status: 400,
                message: format!("Role with ID {} does not exist", id),
                data: None,
            },
            UserError::UserDisabled => HttpResponse {
                status: 403,
                message: "User is disabled".to_string(),
                data: None,
            },
            UserError::NoUpdatesApplied => HttpResponse {
                status: 200,
                message: "No updates applied to user".to_string(),
                data: None,
            },
            UserError::DatabaseError(msg) => HttpResponse {
                status: 500,
                message: format!("Database error: {}", msg),
                data: None,
            },
            UserError::InternalServerError(msg) => HttpResponse {
                status: 500,
                message: format!("Internal server error: {}", msg),
                data: None,
            },
        }
    }
}

// Implement conversion from AppError to UserError
use crate::errors::AppError;

impl From<AppError> for UserError {
    fn from(error: AppError) -> Self {
        match error {
            AppError::InvalidUuid(msg) => UserError::InvalidUuid(msg),
            AppError::UserNotFound(id) => UserError::NotFound(id),
            AppError::RoleNotFound(id) => UserError::RoleNotFound(id),
            AppError::MissingPermissions => UserError::MissingPermissions,
            AppError::SystemUserModification => UserError::SystemUserModification,
            AppError::PasswordHashingError(msg) => UserError::PasswordHashingError(msg),
            AppError::AdminRoleAssignment => UserError::AdminRoleAssignment,
            AppError::NoUpdatesApplied => UserError::NoUpdatesApplied,
            AppError::UserDisabled => UserError::UserDisabled,
            AppError::DatabaseError(msg) => UserError::DatabaseError(msg),
            AppError::InternalServerError(msg) => UserError::InternalServerError(msg),
            _ => UserError::InternalServerError("Unexpected error".to_string()),
        }
    }
}

// Define a Result type alias for user operations
pub type UserResult<T> = Result<T, UserError>;
