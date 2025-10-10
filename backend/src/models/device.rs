use mongodb::bson::{DateTime, Uuid};
use rocket::serde::{Deserialize, Serialize};
use serde_json::json;
use crate::auth::oidc::create_id_token;

#[derive(Debug, Clone, Serialize, Deserialize )]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: Uuid,
    pub token: String,
    pub os: String,
    pub user_agent: String,
    pub ip_address: String,
    pub created_at: DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct DeviceDTO {
    pub id: Uuid,
    pub os: String,
    pub user_agent: String,
    pub ip_address: String,
    pub created_at: DateTime,
}

impl Device {
    pub fn new(user_id: Uuid, os: Option<String>, user_agent: String, ip_adress: Option<String>) -> Self {
        let device_id = Uuid::new();
        Device {
            id: device_id.clone(),
            token: create_id_token(user_id.clone(), user_id, Some(json!({ "deviceId": device_id.to_string() }))).unwrap_or_default(),
            os: os.unwrap_or_else(|| "Unknown".to_string()),
            user_agent: user_agent.to_string(),
            ip_address: ip_adress.unwrap_or_else(|| "Unknown".to_string()),
            created_at: DateTime::now(),
        }
    }

    pub fn to_dto(&self) -> DeviceDTO {
        DeviceDTO {
            id: self.id,
            os: self.os.clone(),
            user_agent: self.user_agent.clone(),
            ip_address: self.ip_address.clone(),
            created_at: self.created_at,
        }
    }
}