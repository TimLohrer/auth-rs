use crate::errors::{ApiError, ApiResult};
use mongodb::bson::Uuid;

/// Parse a string into a UUID, returning an ApiResult
///
/// This is a utility function to reduce code duplication when parsing UUIDs
/// from string parameters in API routes.
pub fn parse_uuid(id: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(id).map_err(|err| ApiError::BadRequest(format!("Invalid UUID: {:?}", err)))
}
