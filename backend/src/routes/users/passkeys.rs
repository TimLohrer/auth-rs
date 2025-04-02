use rocket::{
    http::Status,
    get, patch, delete,
    serde::{json::Json, Deserialize},
};
use rocket_db_pools::Connection;
use mongodb::bson::Uuid;

use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    errors::{ApiError, ApiResult, AppError},
    models::{
        http_response::HttpResponse,
        user::User,
        passkey::PasskeyDTO,
    },
    utils::response::json_response,
};

// DTO for updating passkey metadata
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyUpdateRequest {
    pub device_type: String,
}

// 1. List User's Passkeys
#[get("/users/<user_id>/passkeys")]
pub async fn list_passkeys(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    user_id: String,
) -> (Status, Json<HttpResponse<Vec<PasskeyDTO>>>) {
    let user_uuid = match Uuid::parse_str(&user_id) {
        Ok(id) => id,
        Err(_) => return json_response(ApiError::InvalidUUID.into()),
    };

    // Verify that the user ID in the request matches the authenticated user's ID
    if user_uuid != req_entity.user_id {
        return json_response(ApiError::Unauthorized("Cannot access passkeys for another user".to_string()).into());
    }

    match process_list_passkeys(db, req_entity).await {
        Ok(passkeys) => json_response(HttpResponse {
            status: 200,
            message: "Passkeys retrieved successfully".to_string(),
            data: Some(passkeys),
        }),
        Err(err) => json_response(err.into()),
    }
}

// 2. Update Passkey Metadata
#[patch("/users/<user_id>/passkeys/<passkey_id>", format = "json", data = "<data>")]
pub async fn update_passkey(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    user_id: String,
    passkey_id: String,
    data: Json<PasskeyUpdateRequest>,
) -> (Status, Json<HttpResponse<PasskeyDTO>>) {
    let user_uuid = match Uuid::parse_str(&user_id) {
        Ok(id) => id,
        Err(_) => return json_response(ApiError::InvalidUUID.into()),
    };

    // Verify that the user ID in the request matches the authenticated user's ID
    if user_uuid != req_entity.user_id {
        return json_response(ApiError::Unauthorized("Cannot update passkeys for another user".to_string()).into());
    }

    let passkey_uuid = match Uuid::parse_str(&passkey_id) {
        Ok(id) => id,
        Err(_) => return json_response(ApiError::InvalidUUID.into()),
    };
    
    match process_update_passkey(db, req_entity, passkey_uuid, data.into_inner()).await {
        Ok(passkey) => json_response(HttpResponse {
            status: 200,
            message: "Passkey updated successfully".to_string(),
            data: Some(passkey),
        }),
        Err(err) => json_response(err.into()),
    }
}

// 3. Delete Passkey
#[delete("/users/<user_id>/passkeys/<passkey_id>")]
pub async fn delete_passkey(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    user_id: String,
    passkey_id: String,
) -> (Status, Json<HttpResponse<()>>) {
    let user_uuid = match Uuid::parse_str(&user_id) {
        Ok(id) => id,
        Err(_) => return json_response(ApiError::InvalidUUID.into()),
    };

    // Verify that the user ID in the request matches the authenticated user's ID
    if user_uuid != req_entity.user_id {
        return json_response(ApiError::Unauthorized("Cannot delete passkeys for another user".to_string()).into());
    }

    let passkey_uuid = match Uuid::parse_str(&passkey_id) {
        Ok(id) => id,
        Err(_) => return json_response(ApiError::InvalidUUID.into()),
    };
    
    match process_delete_passkey(db, req_entity, passkey_uuid).await {
        Ok(_) => json_response(HttpResponse {
            status: 200,
            message: "Passkey deleted successfully".to_string(),
            data: None,
        }),
        Err(err) => json_response(err.into()),
    }
}

async fn process_list_passkeys(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
) -> ApiResult<Vec<PasskeyDTO>> {
    // Get the authenticated user
    let user = User::get_by_id(req_entity.user_id, &db).await
        .map_err(|e| ApiError::NotFound(format!("User not found: {}", e)))?;
    
    // Get all passkey DTOs
    Ok(user.get_passkey_dtos())
}

async fn process_update_passkey(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    passkey_id: Uuid,
    data: PasskeyUpdateRequest,
) -> ApiResult<PasskeyDTO> {
    // Get the authenticated user
    let mut user = User::get_by_id(req_entity.user_id, &db).await
        .map_err(|e| ApiError::NotFound(format!("User not found: {}", e)))?;
    
    // Find the passkey
    let passkey = user.find_passkey_by_id(&passkey_id)
        .ok_or(ApiError::NotFound("Passkey not found".to_string()))?
        .clone();
    
    // Create updated passkey
    let mut updated_passkey = passkey.clone();
    updated_passkey.device_type = data.device_type;
    
    // Update the user
    user.remove_passkey(&passkey_id);
    user.add_passkey(updated_passkey.clone());
    user.update(&db).await
        .map_err(|e| ApiError::AppError(AppError::DatabaseError(e.to_string())))?;
    
    Ok(updated_passkey.to_dto())
}

async fn process_delete_passkey(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    passkey_id: Uuid,
) -> ApiResult<()> {
    // Get the authenticated user
    let mut user = User::get_by_id(req_entity.user_id, &db).await
        .map_err(|e| ApiError::NotFound(format!("User not found: {}", e)))?;
    
    // Try to find and remove the passkey
    if !user.remove_passkey(&passkey_id) {
        return Err(ApiError::NotFound("Passkey not found".to_string()));
    }
    
    // Update the user
    user.update(&db).await
        .map_err(|e| ApiError::AppError(AppError::DatabaseError(e.to_string())))?;
    
    Ok(())
} 