use mongodb::bson::{doc, Uuid};
use rocket::serde::{Deserialize, Serialize};
use base64::{engine::general_purpose, Engine as _};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct Passkey {
    pub id: Uuid,
    pub credential_id: String,
    pub public_key: String,
    pub counter: u32,
    pub transports: Option<Vec<String>>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub device_type: String,
    pub created_at: mongodb::bson::DateTime,
}

// DTO for API responses with less sensitive data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyDTO {
    pub id: Uuid,
    pub device_type: String,
    pub created_at: mongodb::bson::DateTime,
}

impl Passkey {
    pub fn new(
        credential_id: Vec<u8>,
        public_key: String,
        counter: u32,
    ) -> Self {
        Self {
            id: Uuid::new(),
            credential_id: general_purpose::STANDARD.encode(&credential_id),
            public_key,
            counter,
            transports: None,
            backup_eligible: true,
            backup_state: false,
            device_type: "unknown".to_string(),
            created_at: mongodb::bson::DateTime::now(),
        }
    }

    pub fn get_credential_id_bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        general_purpose::STANDARD.decode(&self.credential_id)
    }
    
    // Convert to DTO
    pub fn to_dto(&self) -> PasskeyDTO {
        PasskeyDTO {
            id: self.id,
            device_type: self.device_type.clone(),
            created_at: self.created_at,
        }
    }
} 