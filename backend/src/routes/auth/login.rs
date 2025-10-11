use mongodb::bson::Uuid;
use rocket::http::Status;
use rocket::{
    post,
    serde::{json::Json, Deserialize, Serialize},
};
use rocket_db_pools::Connection;
use user_agent_parser::{UserAgent, OS};

use crate::auth::IpAddr;
use crate::errors::AppError;
use crate::models::audit_log::{AuditLog, AuditLogAction, AuditLogEntityType};
use crate::models::user::UserDTO;
use crate::models::user_error::UserError;
use crate::utils::response::json_response;
use crate::{
    auth::mfa::MfaHandler,
    db::AuthRsDatabase,
    errors::{ApiError, ApiResult},
    models::{http_response::HttpResponse, user::User},
};

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct LoginData {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub user: Option<UserDTO>,
    pub token: Option<String>,
    pub mfa_required: bool,
    pub mfa_flow_id: Option<Uuid>,
}

// Process login and return a Result
async fn process_login(
    db: &Connection<AuthRsDatabase>,
    login_data: LoginData,
    user_agent: UserAgent<'_>,
    os: OS<'_>,
    ip: IpAddr
) -> ApiResult<LoginResponse> {
    let mut user = User::get_by_email(&login_data.email, db)
        .await
        .map_err(|err| ApiError::InternalError(err.to_string()))?;

    if user.disabled {
        return Err(ApiError::Forbidden("User is disabled".to_string()));
    }

    if user.verify_password(&login_data.password).is_err() {
        return Err(ApiError::Unauthorized(
            "Invalid email or password".to_string(),
        ));
    }

    if MfaHandler::is_mfa_required(&user) {
        let mfa_flow = MfaHandler::start_login_flow(&user)
            .await
            .map_err(|err| ApiError::InternalError(format!("Failed to start MFA flow: {}", err)))?;

        return Ok(LoginResponse {
            user: None,
            token: None,
            mfa_required: true,
            mfa_flow_id: Some(mfa_flow.flow_id),
        });
    }

    user.cleanup_expired_devices(&db).await.ok();

    let device = match user.get_device(&db, os, user_agent, ip)
        .await {
            Ok(device) => device,
            Err(err) => match err {
                UserError::MaxDevicesReached => return Err(ApiError::AppError(AppError::DeviceError("Maximum number of devices reached. Please remove an existing device before adding a new one.".to_string()))),
                _ => return Err(ApiError::AppError(AppError::DeviceError("Failed to get or create device.".to_string()))),
            },
        };

    Ok(LoginResponse {
        user: Some(user.to_dto(true)),
        token: Some(device.token),
        mfa_required: false,
        mfa_flow_id: None,
    })
}

#[allow(unused)]
#[post("/auth/login", format = "json", data = "<data>")]
pub async fn login(
    db: Connection<AuthRsDatabase>,
    data: Json<LoginData>,
    user_agent: UserAgent<'_>,
    os: OS<'_>,
    ip: IpAddr
) -> (Status, Json<HttpResponse<LoginResponse>>) {
    let login_data = data.into_inner();

    match process_login(&db, login_data, user_agent, os, ip).await {
        Ok(response) => {
            if response.user.is_some() {
                AuditLog::new(
                    response.user.clone().unwrap().id.to_string(),
                    AuditLogEntityType::User,
                    AuditLogAction::Login,
                    "Login successful.".to_string(),
                    response.user.clone().unwrap().id,
                    None,
                    None,
                )
                .insert(&db)
                .await
                .ok();
            }

            let message = if response.mfa_required {
                "MFA required"
            } else {
                "Login successful"
            };
            json_response(HttpResponse::success(message, response))
        }
        Err(err) => json_response(err.into()),
    }
}
