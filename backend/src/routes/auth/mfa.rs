use std::collections::HashMap;

use mongodb::bson::Uuid;
use rocket::{
    post,
    serde::{json::Json, Deserialize, Serialize},
};
use rocket_db_pools::Connection;
use totp_rs::TOTP;

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

use super::login::LoginResponse;

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
) -> ApiResult<(String, LoginResponse)> {
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

    if flow.r#type != MfaType::TOTP && flow.r#type != MfaType::EnableTOTP {
        return Err(ApiError::BadRequest("Invalid MFA type".to_string()));
    }

    if !flow.verify_current_totp(&mfa_data.code).await {
        return Err(ApiError::Unauthorized("Invalid TOTP code".to_string()));
    }

    if flow.r#type == MfaType::EnableTOTP && flow.totp.is_some() && flow.user.totp_secret.is_none()
    {
        let mut user = flow.user.clone();
        user.totp_secret = Some(flow.totp.as_ref().unwrap().get_secret_base32());

        user.update(db)
            .await
            .map_err(|err| ApiError::InternalError(format!("Failed to enable TOTP: {:?}", err)))?;

        let new_values = HashMap::from([(
            "totpSecret".to_string(),
            user.totp_secret
                .as_ref()
                .unwrap_or(&"".to_string())
                .to_string(),
        )]);
        let old_values = HashMap::from([("totpSecret".to_string(), "".to_string())]);

        if let Err(err) = AuditLog::new(
            user.id,
            AuditLogEntityType::User,
            AuditLogAction::Update,
            "Enable TOTP.".to_string(),
            user.id,
            Some(old_values),
            Some(new_values),
        )
        .insert(db)
        .await
        {
            eprintln!("{:?}", err);
        }

        Ok((
            "TOTP enabled".to_string(),
            LoginResponse {
                user: Some(user.to_dto()),
                token: Some(TOTP::get_qr_base64(flow.totp.as_ref().unwrap()).unwrap()),
                mfa_required: false,
                mfa_flow_id: None,
            },
        ))
    } else {
        Ok((
            "MFA complete".to_string(),
            LoginResponse {
                user: Some(flow.user.to_dto()),
                token: Some(flow.user.token.to_string()),
                mfa_required: false,
                mfa_flow_id: None,
            },
        ))
    }
}

#[allow(unused)]
#[post("/auth/mfa", format = "json", data = "<data>")]
pub async fn mfa(
    db: Connection<AuthRsDatabase>,
    data: Json<MfaData>,
) -> Json<HttpResponse<LoginResponse>> {
    let mfa_data = data.into_inner();

    match process_mfa(&db, mfa_data).await {
        Ok((message, response)) => Json(HttpResponse::success(&message, response)),
        Err(err) => Json(err.into()),
    }
}
