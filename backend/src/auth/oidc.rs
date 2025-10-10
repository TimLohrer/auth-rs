use mongodb::bson::Uuid;
use rocket::time::OffsetDateTime;
use serde_json::Value;
use std::sync::Arc;
use rsa::{RsaPrivateKey, RsaPublicKey};
use anyhow::Result;
use crate::auth::jwt::{Claims, sign_id_token, ensure_keys_exist};
use crate::utils::base_urls::get_base_domain;

#[derive(Clone)]
pub struct OidcKeys {
    #[allow(unused)]
    pub private: Arc<RsaPrivateKey>,
    pub public: Arc<RsaPublicKey>,
    pub kid: String,
}

pub fn create_id_token(user_id: Uuid, aud: Uuid, data: Option<Value>) -> Result<String> {
    ensure_keys_exist()?;

    let now = OffsetDateTime::now_utc().unix_timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        aud: aud.to_string(),
        iss: get_base_domain(),
        exp: (now + 60 * 60 * 24) as usize,
        iat: now as usize,
        data
    };

    let token = sign_id_token(&claims)?;
    Ok(token)
}