use anyhow::Result;
use mongodb::bson::{DateTime, Uuid};
use rocket::serde::{Deserialize, Serialize};
use serde_json::json;
use crate::{auth::oidc::create_id_token, models::user_error::UserError};

#[derive(Debug, Clone, Serialize, Deserialize )]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: Uuid,
    pub token: String,
    pub os: String,
    pub user_agent: String,
    pub ip_address: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct DeviceDTO {
    pub id: Uuid,
    pub os: String,
    pub user_agent: String,
    pub ip_address: String,
    pub created_at: i64,
}

impl Device {
    pub fn new(user_id: Uuid, os: Option<String>, user_agent: String, ip_address: Option<String>) -> Result<Self, UserError> {
        let device_id = Uuid::new();
        let token = match create_id_token(
            user_id.clone(),
            user_id,
            Some(json!({ "deviceId": device_id.to_string() })),
        ) {
            Ok(token) => token,
            Err(err) => return Err(UserError::InternalServerError(err.to_string()))
        };
        Ok(Device {
            id: device_id.clone(),
            token,
            os: os.unwrap_or_else(|| "Unknown".to_string()),
            user_agent: user_agent.to_string(),
            ip_address: ip_address.unwrap_or_else(|| "Unknown".to_string()),
            created_at: DateTime::now().timestamp_millis(),
        })
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