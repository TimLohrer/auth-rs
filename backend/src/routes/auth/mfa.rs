use mongodb::bson::Uuid;
use rocket::http::Status;
use rocket::{
    post,
    serde::{json::Json, Deserialize, Serialize},
};
use rocket_db_pools::Connection;
use user_agent_parser::{UserAgent, OS};
use std::collections::HashMap;
use totp_rs::TOTP;

use super::login::LoginResponse;
use crate::auth::auth::IpAddr;
use crate::errors::AppError;
use crate::models::device::Device;
use crate::models::user_error::UserError;
use crate::utils::response::json_response;
use crate::{
    auth::mfa::{MfaState, MfaType},
    db::AuthRsDatabase,
    errors::{ApiError, ApiResult},
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
    },
    MFA_SESSIONS,
};

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct MfaData {
    pub flow_id: Uuid,
    pub code: String,
}

// Process MFA verification and return a Result
async fn process_mfa(
    db: &Connection<AuthRsDatabase>,
    mfa_data: MfaData,
    user_agent: UserAgent<'_>,
    os: OS<'_>,
    ip: IpAddr
) -> ApiResult<(String, LoginResponse, Option<Device>)> {
    let mfa_sessions = MFA_SESSIONS.lock().await;
    let cloned_sessions = mfa_sessions.clone();

    let flow = cloned_sessions
        .get(&mfa_data.flow_id)
        .ok_or_else(|| ApiError::NotFound("Invalid or expired MFA flow".to_string()))?;

    drop(mfa_sessions);

    if flow.state == MfaState::Complete {
        return Err(ApiError::BadRequest(
            "MFA flow already complete".to_string(),
        ));
    }

    if flow.r#type != MfaType::Totp && flow.r#type != MfaType::EnableTotp {
        return Err(ApiError::BadRequest("Invalid MFA type".to_string()));
    }

    if !flow.verify_current_totp(&mfa_data.code).await {
        return Err(ApiError::Unauthorized("Invalid TOTP code".to_string()));
    }

    if flow.r#type == MfaType::EnableTotp && flow.totp.is_some() && flow.user.totp_secret.is_none()
    {
        let mut user = flow.user.clone();
        user.totp_secret = Some(flow.totp.as_ref().unwrap().get_secret_base32());

        user.update(db)
            .await
            .map_err(|err| ApiError::InternalError(format!("Failed to enable TOTP: {:?}", err)))?;

        let new_values = HashMap::from([("totp_secret".to_string(), "*************".to_string())]);
        let old_values = HashMap::from([("totp_secret".to_string(), "".to_string())]);

        AuditLog::new(
            user.id.to_string(),
            AuditLogEntityType::User,
            AuditLogAction::Update,
            "Enable TOTP.".to_string(),
            user.id,
            Some(old_values),
            Some(new_values),
        )
        .insert(db)
        .await
        .ok();

        Ok((
            "TOTP enabled".to_string(),
            LoginResponse {
                user: Some(user.to_dto(true)),
                token: Some(TOTP::get_qr_base64(flow.totp.as_ref().unwrap()).unwrap()),
                mfa_required: false,
                mfa_flow_id: None,
            },
            None
        ))
    } else {
        let mut user = flow.user.clone();

        flow.user.clone().cleanup_expired_devices(&db).await.ok();

        let device = match user.get_device(&db, os, user_agent, ip)
        .await {
            Ok(device) => device,
            Err(err) => match err {
                UserError::MaxDevicesReached => return Err(ApiError::AppError(AppError::DeviceError("Maximum number of devices reached. Please remove an existing device before adding a new one.".to_string()))),
                _ => return Err(ApiError::AppError(AppError::DeviceError("Failed to get or create device.".to_string()))),
            },
        };

        Ok((
            "MFA complete".to_string(),
            LoginResponse {
                user: Some(user.to_dto(true)),
                token: Some(device.token.clone()),
                mfa_required: false,
                mfa_flow_id: None,
            },
            Some(device)
        ))
    }
}

#[allow(unused)]
#[post("/auth/mfa", format = "json", data = "<data>")]
pub async fn mfa(
    db: Connection<AuthRsDatabase>,
    data: Json<MfaData>,
    user_agent: UserAgent<'_>,
    os: OS<'_>,
    ip: IpAddr
) -> (Status, Json<HttpResponse<LoginResponse>>) {
    let mfa_data = data.into_inner();

    match process_mfa(&db, mfa_data, user_agent, os, ip).await {
        Ok((message, response, device)) => {
            if message == "MFA complete" {
                AuditLog::new(
                    response.user.clone().unwrap().id.to_string(),
                    AuditLogEntityType::User,
                    AuditLogAction::Login,
                    "MFA login successful.".to_string(),
                    response.user.clone().unwrap().id,
                    None,
                    Some(HashMap::from([("userAgent".to_string(), device.clone().unwrap().user_agent), ("os".to_string(), device.clone().unwrap().os), ("ip".to_string(), device.unwrap().ip_address)])),
                )
                .insert(&db)
                .await
                .ok();
            }

            json_response(HttpResponse::success(&message, response))
        }
        Err(err) => json_response(err.into()),
    }
}
