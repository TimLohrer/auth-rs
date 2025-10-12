use rocket::{delete, http::Status, serde::json::Json};
use rocket_db_pools::Connection;

use crate::models::passkey::Passkey;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    errors::{ApiError, ApiResult, AppError},
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
    },
    utils::response::json_response,
};

#[delete("/passkeys/<passkey_id>")]
pub async fn delete_passkey(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    passkey_id: String,
) -> (Status, Json<HttpResponse<()>>) {
    let passkey = match Passkey::get_by_id(passkey_id.as_str(), &db).await {
        Ok(passkey) => passkey,
        Err(_) => return json_response(ApiError::NotFound("Passkey not found".to_string()).into()),
    };

    // Verify that the user ID in the request matches the authenticated user's ID
    if passkey.owner != req_entity.user_id {
        return json_response(
            ApiError::Unauthorized("Cannot delete passkeys for another user".to_string()).into(),
        );
    }

    match process_delete_passkey(db, passkey_id.as_str(), req_entity).await {
        Ok(_) => json_response(HttpResponse {
            status: 200,
            message: "Passkey deleted successfully".to_string(),
            data: None,
        }),
        Err(err) => json_response(err.into()),
    }
}

async fn process_delete_passkey(
    db: Connection<AuthRsDatabase>,
    passkey_id: &str,
    req_entity: AuthEntity,
) -> ApiResult<()> {
    // Get the authenticated user
    let passkey = Passkey::get_by_id(passkey_id, &db)
        .await
        .map_err(|e| ApiError::NotFound(format!("User not found: {}", e)))?;

    // Update the user
    passkey
        .delete(&db)
        .await
        .map_err(|e| ApiError::AppError(AppError::DatabaseError(e.to_string())))?;

    AuditLog::new(
        passkey.id,
        AuditLogEntityType::Passkey,
        AuditLogAction::Delete,
        "Passkey deleted.".to_string(),
        req_entity.user_id,
        None,
        None,
    )
    .insert(&db)
    .await
    .ok();

    Ok(())
}
