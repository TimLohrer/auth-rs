use crate::errors::AppError;
use mongodb::bson::Uuid;

pub fn parse_uuid(id: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(id).map_err(|_| AppError::InvalidUuid(id.to_string()))
}
