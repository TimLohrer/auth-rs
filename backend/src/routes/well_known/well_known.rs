use lazy_static::lazy_static;
use rocket::{get, serde::json::Json, State};
use serde_json::{Value, json};

use crate::{auth::{jwk::jwk_from_pubkey, oidc::OidcKeys}, utils::base_urls::{get_application_name, get_base_domain}};

lazy_static! {
    static ref CONFIGURATION: Value = json!({
        "issuer": get_application_name(),
        "authorization_endpoint": format!("{}/api/oauth/authorize", get_base_domain()),
        "token_endpoint": format!("{}/api/oauth/token", get_base_domain()),
        "userinfo_endpoint": format!("{}/api/users/@me/plain", get_base_domain()),
        "jwks_uri": format!("{}/.well-known/jwks.json", get_base_domain()),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": [
            "user:read",
            "user:update",
            "user:*",
            "user_data_storage:read",
            "user_data_storage:update",
            "user_data_storage:*",
            "roles:read",
            "audit_logs:read",
            "oauth_applications:read",
            "connections:read",
            "connections:delete",
            "connections:*"
        ],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"]
    });
}

#[get("/.well-known/openid-configuration")]
pub fn discovery() -> Json<Value> {
    Json(CONFIGURATION.clone())
}

#[get("/.well-known/jwks.json")]
pub fn jwks(keys: &State<OidcKeys>) -> Json<Value> {
    let jwk = jwk_from_pubkey(&keys.public, &keys.kid);
    Json(json!({ "keys": [jwk] }))
}