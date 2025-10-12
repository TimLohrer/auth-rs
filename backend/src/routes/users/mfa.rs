use rocket::http::Status;
use rocket::{
    post,
    serde::{json::Json, Deserialize},
};
use rocket_db_pools::Connection;

use crate::models::user::UserDTO;
use crate::utils::response::json_response;
use crate::{
    auth::{mfa::MfaHandler, auth::AuthEntity},
    db::AuthRsDatabase,
    errors::{ApiError, ApiResult},
    models::{http_response::HttpResponse, user::User},
    routes::auth::login::LoginResponse,
    utils::parse_uuid::parse_uuid,
};

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct EnableMfaData {
    pub password: String,
}

// Process enable TOTP MFA and return a Result
async fn process_enable_totp_mfa(
    db: &Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    mfa_data: EnableMfaData,
) -> ApiResult<(String, LoginResponse)> {
    if req_entity.is_token() {
        return Err(ApiError::Forbidden("Forbidden!".to_string()));
    }

    let uuid = parse_uuid(id)?;

    if req_entity.is_user()
        && req_entity.user_id != uuid
        && !req_entity.user.as_ref().unwrap().is_system_admin()
    {
        return Err(ApiError::Forbidden("Missing permissions!".to_string()));
    }

    let user = User::get_by_id(uuid, db)
        .await
        .map_err(|err| ApiError::InternalError(format!("Failed to get user: {:?}", err)))?;

    if user.verify_password(&mfa_data.password).is_err() {
        return Err(ApiError::Unauthorized("Incorrect password!".to_string()));
    }

    if user.totp_secret.is_some() {
        return Err(ApiError::BadRequest(
            "TOTP MFA is already enabled!".to_string(),
        ));
    }

    let flow = MfaHandler::start_enable_flow(&user)
        .await
        .map_err(|err| ApiError::InternalError(format!("Failed to start MFA flow: {}", err)))?;

    Ok((
        "TOTP MFA enable flow started.".to_string(),
        LoginResponse {
            user: Some(user.to_dto(false)),
            token: Some(flow.totp.unwrap().get_qr_base64().unwrap()),
            mfa_required: true,
            mfa_flow_id: Some(flow.flow_id),
        },
    ))
}

#[allow(unused)]
#[post("/users/<id>/mfa/totp/enable", format = "json", data = "<data>")]
pub async fn enable_totp_mfa(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    data: Json<EnableMfaData>,
) -> (Status, Json<HttpResponse<LoginResponse>>) {
    let mfa_data = data.into_inner();

    match process_enable_totp_mfa(&db, req_entity, id, mfa_data).await {
        Ok((message, response)) => json_response(HttpResponse::success(&message, response)),
        Err(err) => json_response(err.into()),
    }
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct DisableMfaData {
    pub code: Option<String>,
}

// Process disable TOTP MFA and return a Result
async fn process_disable_totp_mfa(
    db: &Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    mfa_data: DisableMfaData,
) -> ApiResult<User> {
    if req_entity.is_token() {
        return Err(ApiError::Forbidden("Forbidden!".to_string()));
    }

    let uuid = parse_uuid(id)?;

    if req_entity.is_user()
        && req_entity.user_id != uuid
        && !req_entity.user.as_ref().unwrap().is_system_admin()
    {
        return Err(ApiError::Forbidden("Missing permissions!".to_string()));
    }

    let mut user = User::get_by_id(uuid, db)
        .await
        .map_err(|err| ApiError::InternalError(format!("Failed to get user: {:?}", err)))?;

    if user.totp_secret.is_none() {
        return Err(ApiError::BadRequest("TOTP MFA is not enabled!".to_string()));
    }

    if mfa_data.code.is_none() && !req_entity.user.as_ref().unwrap().is_system_admin() {
        return Err(ApiError::BadRequest(
            "Missing TOTP code!".to_string(),
        ));
    }

    if let Some(code) = mfa_data.code {
        let is_valid =
            MfaHandler::verify_totp(&user, user.totp_secret.as_ref().unwrap().to_string(), &code)
                .await;

        if !is_valid {
            return Err(ApiError::Forbidden("Invalid TOTP code!".to_string()));
        }
    }

    let updated_user = MfaHandler::disable_totp(&mut user, req_entity, db)
        .await
        .map_err(|err| ApiError::InternalError(format!("Failed to disable TOTP: {:?}", err)))?;

    Ok(updated_user)
}

#[allow(unused)]
#[post("/users/<id>/mfa/totp/disable", format = "json", data = "<data>")]
pub async fn disable_totp_mfa(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    data: Json<DisableMfaData>,
) -> Json<HttpResponse<UserDTO>> {
    let mfa_data = data.into_inner();

    match process_disable_totp_mfa(&db, req_entity, id, mfa_data).await {
        Ok(user) => Json(HttpResponse::success("TOTP MFA disabled.", user.to_dto(true))),
        Err(err) => Json(err.into()),
    }
}
