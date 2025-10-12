use rocket::{get, http::Status, serde::json::Json};
use rocket_db_pools::Connection;

use crate::models::passkey::Passkey;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    errors::{ApiError, ApiResult},
    models::{http_response::HttpResponse, passkey::PasskeyDTO},
    utils::response::json_response,
};

#[get("/passkeys")]
pub async fn list_passkeys(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
) -> (Status, Json<HttpResponse<Vec<PasskeyDTO>>>) {
    if !req_entity.is_user() || !req_entity.user.as_ref().unwrap().is_admin() {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    match process_list_passkeys(db).await {
        Ok(passkeys) => json_response(HttpResponse {
            status: 200,
            message: "Passkeys retrieved successfully".to_string(),
            data: Some(passkeys),
        }),
        Err(err) => json_response(err.into()),
    }
}

async fn process_list_passkeys(db: Connection<AuthRsDatabase>) -> ApiResult<Vec<PasskeyDTO>> {
    // Get the authenticated user
    let passkeys = Passkey::get_all(&db, None)
        .await
        .map_err(|e| ApiError::NotFound(format!("User not found: {}", e)))?
        .iter()
        .map(|passkey| passkey.to_dto())
        .collect();

    // Get all passkey DTOs
    Ok(passkeys)
}
