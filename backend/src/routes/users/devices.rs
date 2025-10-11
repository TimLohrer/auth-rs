use std::collections::HashMap;

use rocket::{delete, get, http::Status, serde::{self, json::Json}};
use rocket_db_pools::Connection;

use crate::{auth::{mfa::MfaHandler, AuthEntity}, db::AuthRsDatabase, models::{audit_log::{AuditLog, AuditLogAction, AuditLogEntityType}, device::DeviceDTO, http_response::HttpResponse, user_error::UserError}, utils::{parse_uuid::parse_uuid, response::json_response}};

#[allow(unused)]
#[get("/users/<user_id>/devices")]
pub async fn get_all_user_devices(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    user_id: &str
) -> (Status, Json<HttpResponse<Vec<DeviceDTO>>>) {
    if !req_entity.is_user() {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    let uuid = match parse_uuid(user_id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };

    let user = req_entity.user.as_ref().unwrap();

    if req_entity.user_id != uuid && !user.is_admin() {
        return json_response(HttpResponse::forbidden("Missing permissions!"));
    }

    json_response(HttpResponse {
        status: 200,
        message: "User devices fetched".to_string(),
        data: Some(user.devices.iter().map(|d| d.to_dto()).collect::<Vec<DeviceDTO>>()),
    })
}

#[allow(unused)]
#[delete("/users/<user_id>/devices/<device_id>")]
pub async fn delete_user_device(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    user_id: &str,
    device_id: &str
) -> (Status, Json<HttpResponse<()>>) {
    if !req_entity.is_user() {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    let user_uuid = match parse_uuid(user_id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };

    let device_uuid = match parse_uuid(device_id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };

    let user = req_entity.user.as_ref().unwrap();

    if req_entity.user_id != user_uuid && !user.is_admin() {
        return json_response(HttpResponse::forbidden("Missing permissions!"));
    }

    let opt_device = user.devices.iter().find(|d| &d.id.to_string() == device_id);

    if opt_device.is_none() {
        return json_response(HttpResponse::not_found("Device not found"));
    }

    let device = opt_device.unwrap();

    match user.remove_device(device_uuid, &db).await {
        Ok(_) => {}
        Err(err) => match err {
            UserError::DatabaseError(db_err) => {
                return json_response(HttpResponse::internal_error(&db_err));
            }
            _ => {
                return json_response(HttpResponse::internal_error("Internal server error"));
            }
        }
    };

    AuditLog::new(
        user.id.to_string(),
        AuditLogEntityType::User,
        AuditLogAction::Update,
        "Device removed".to_string(),
        req_entity.user_id,
        Some(HashMap::from([("deviceId".to_string(), device_id.to_string()), ("userAgent".to_string(), device.user_agent.clone()), ("os".to_string(), device.os.clone()), ("ip".to_string(), device.ip_address.clone())])),
        None,
    ).insert(&db).await.ok();

    json_response(HttpResponse {
        status: 200,
        message: "Device removed".to_string(),
        data: None,
    })
}

#[derive(serde::Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct DeleteAllDevicesRequest {
    pub password: Option<String>,
    pub totp: Option<String>,
}

#[allow(unused)]
#[delete("/users/<user_id>/devices", format = "json", data = "<data>")]
pub async fn delete_all_user_devices(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    user_id: &str,
    data: Json<DeleteAllDevicesRequest>
) -> (Status, Json<HttpResponse<()>>) {
    let data = data.into_inner();

    if !req_entity.is_user() {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    let user_uuid = match parse_uuid(user_id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };
    
    let user = req_entity.user.as_ref().unwrap();

    if req_entity.user_id != user_uuid && !user.is_admin() {
        return json_response(HttpResponse::forbidden("Missing permissions!"));
    }

    // only verify password/totp if the user is deleting their own devices
    if req_entity.user_id == user_uuid {
        if user.totp_secret != None && data.totp.is_none() {
            return json_response(HttpResponse::bad_request("TOTP code required"));
        } else if user.totp_secret != None && data.totp.is_some() {
            if !MfaHandler::verify_totp(&user.clone(), user.totp_secret.clone().unwrap(), data.totp.unwrap().as_str()).await {
                return json_response(HttpResponse::unauthorized("Invalid TOTP code"));
            }
        } else if user.totp_secret == None && data.password.is_none() {
            return json_response(HttpResponse::bad_request("Password required"));
        } else if user.totp_secret == None && data.password.is_some() {
            if user.verify_password(data.password.unwrap().as_str()).is_err() {
                return json_response(HttpResponse::unauthorized("Invalid password"));
            }
        }
    }

    match user.remove_all_devices(&db).await {
        Ok(_) => {}
        Err(err) => match err {
            UserError::DatabaseError(db_err) => {
                return json_response(HttpResponse::internal_error(&db_err));
            }
            _ => {
                return json_response(HttpResponse::internal_error("Internal server error"));
            }
        }
    };

    AuditLog::new(
        user.id.to_string(),
        AuditLogEntityType::User,
        AuditLogAction::Update,
        "All devices removed".to_string(),
        req_entity.user_id,
        None,
        None,
    ).insert(&db).await.ok();

    json_response(HttpResponse {
        status: 200,
        message: "All devices removed".to_string(),
        data: None,
    })
}
