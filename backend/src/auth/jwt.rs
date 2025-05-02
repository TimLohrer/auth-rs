use std::env;

use jsonwebtoken::Algorithm;
use mongodb::bson::DateTime;

pub struct AuthRsJWTClaims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
}

impl AuthRsJWTClaims {
    pub fn new(sub: String) -> Self {
        Self {
            sub,
            exp: 0,
            iat: DateTime::now().timestamp_millis() as usize,
            iss: env::var("TOTP_ISSUER_NAME").unwrap_or_else(|_| "auth-rs".to_string()),
        }
    }
}

pub struct AuthRsJWTHandler {
    pub secret: String,
    pub algorithm: Algorithm
}

impl AuthRsJWTHandler {
    pub fn new() -> Self {
        Self { secret: env::_var("JWT_SECRET").unwrap_or(panic!("Please provide the JWT_SECRET environment variable!")), algorithm: Algorithm::HS256 }
    }

    pub fn generate_token(&self, claims: AuthRsJWTClaims) -> Result<String, String> {
        let header = Header::new(self.algorithm);
        let token = encode(&header, &claims, &self.secret).map_err(|e| e.to_string())?;
        Ok(token)
    }

    pub fn validate_token(&self, token: &str) -> Result<AuthRsJWTClaims, String> {
        let token_data = decode::<AuthRsJWTClaims>(token, &self.secret, self.algorithm)
            .map_err(|e| e.to_string())?;
        Ok(token_data.claims)
    }
}