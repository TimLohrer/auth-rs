use std::collections::HashMap;

use rocket::{
    http::Status,
    patch,
    serde::{json::Json, Deserialize},
};
use rocket_db_pools::Connection;

use crate::models::passkey::Passkey;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    errors::{ApiError, ApiResult, AppError},
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
        passkey::PasskeyDTO,
    },
    utils::response::json_response,
};

// DTO for updating passkey metadata
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyUpdateRequest {
    pub name: Option<String>,
}

#[patch("/passkeys/<passkey_id>", format = "json", data = "<data>")]
pub async fn update_passkey(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    passkey_id: String,
    data: Json<PasskeyUpdateRequest>,
) -> (Status, Json<HttpResponse<PasskeyDTO>>) {
    let passkey = match Passkey::get_by_id(passkey_id.as_str(), &db).await {
        Ok(passkey) => passkey,
        Err(_) => return json_response(ApiError::NotFound("Passkey not found".to_string()).into()),
    };

    // Verify that the user ID in the request matches the authenticated user's ID
    if passkey.owner != req_entity.user_id {
        return json_response(
            ApiError::Unauthorized("Cannot update passkeys for another user".to_string()).into(),
        );
    }

    match process_update_passkey(db, passkey_id.as_str(), data.into_inner(), req_entity).await {
        Ok(passkey) => json_response(HttpResponse {
            status: 200,
            message: "Passkey updated successfully".to_string(),
            data: Some(passkey),
        }),
        Err(err) => json_response(err.into()),
    }
}

async fn process_update_passkey(
    db: Connection<AuthRsDatabase>,
    passkey_id: &str,
    data: PasskeyUpdateRequest,
    req_entity: AuthEntity,
) -> ApiResult<PasskeyDTO> {
    // Get the authenticated user
    let passkey = Passkey::get_by_id(passkey_id, &db)
        .await
        .map_err(|e| ApiError::NotFound(format!("User not found: {}", e)))?;

    // Create updated passkey
    let mut updated_passkey = passkey.clone();

    if data.name.is_some() {
        updated_passkey.name = data.name.unwrap();

        updated_passkey
            .update(&db)
            .await
            .map_err(|e| ApiError::AppError(AppError::DatabaseError(e.to_string())))?;

        let old_values = HashMap::from([("name".to_string(), passkey.name.clone())]);

        let new_values = HashMap::from([("name".to_string(), updated_passkey.name.clone())]);

        AuditLog::new(
            passkey.id,
            AuditLogEntityType::Passkey,
            AuditLogAction::Update,
            "Passkey updated.".to_string(),
            req_entity.user_id,
            Some(old_values),
            Some(new_values),
        )
        .insert(&db)
        .await
        .ok();
    }

    Ok(updated_passkey.to_dto())
}
