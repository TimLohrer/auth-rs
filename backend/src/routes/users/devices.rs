use rocket::{delete, get, http::Status, serde::{self, json::Json}};
use rocket_db_pools::Connection;

use crate::{auth::{mfa::MfaHandler, AuthEntity, RequestHeaders}, db::AuthRsDatabase, models::{device::DeviceDTO, http_response::HttpResponse, user_error::UserError}, utils::{parse_uuid::parse_uuid, response::json_response}};

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
        data: Some(user.devices.clone().into_iter().map(|d| d.to_dto()).collect::<Vec<DeviceDTO>>()),
    })
}

#[allow(unused)]
#[delete("/users/<user_id>/devices/<device_id>")]
pub async fn delete_user_device(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    headers: RequestHeaders,
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

    if !user.devices.iter().any(|d| d.id == device_uuid) {
        return json_response(HttpResponse::not_found("Device not found"));
    }

    let device = user.devices.iter().find(|d| d.id == device_uuid).unwrap();
    if device.token == headers.headers.iter().find(|(name, _)| name.to_lowercase() == "authorization").map(|(_, value)| value.replace("Bearer ", "")).unwrap_or_default() {
        return json_response(HttpResponse::bad_request("Cannot remove current device"));
    }

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

    json_response(HttpResponse {
        status: 200,
        message: "All devices removed".to_string(),
        data: None,
    })
}
