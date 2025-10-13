use mongodb::bson::Uuid;
use rocket::http::Status;
use rocket::{
    error, post,
    serde::{json::Json, Deserialize},
};
use rocket_db_pools::Connection;

use crate::models::registration_token::RegistrationTokenDTO;
use crate::models::role::Role;
use crate::utils::response::json_response;
use crate::DEFAULT_ROLE_ID;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
        registration_token::RegistrationToken,
    },
};

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct CreateRegistrationTokenData {
    max_uses: Option<u32>,
    expires_in: Option<u64>,
    auto_roles: Option<Vec<Uuid>>,
}

#[allow(unused)]
#[post("/registration-tokens", format = "json", data = "<data>")]
pub async fn create_registration_token(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    data: Json<CreateRegistrationTokenData>,
 ) -> (Status, Json<HttpResponse<RegistrationTokenDTO>>) {
    let data = data.into_inner();

    if !req_entity.is_user() || !req_entity.user.unwrap().is_admin() {
        return json_response(HttpResponse::forbidden(
            "Only admins can create registration tokens",
        ));
    }

    if data.auto_roles.is_some() {
        for role_id in data.auto_roles.as_ref().unwrap() {
            Role::get_by_id(*role_id, &db)
                .await
                .map_err(|err| {
                    error!("{}", err);
                    json_response::<HttpResponse<()>>(err.into())
                })
                .ok();
        }
    }

    let registration_token = match RegistrationToken::new(
        data.max_uses,
        data.expires_in,
        data.auto_roles.as_ref().map(|roles| {
            roles
                .iter()
                .filter(|role_id| **role_id != *DEFAULT_ROLE_ID)
                .cloned()
                .collect::<Vec<Uuid>>()
        }),
    ) {
        Ok(registration_token) => registration_token,
        Err(err) => return json_response(err.into()),
    };

    match registration_token.insert(&db).await {
        Ok(registration_token) => {
            match AuditLog::new(
                registration_token.id.to_string(),
                AuditLogEntityType::RegistrationToken,
                AuditLogAction::Create,
                "Registration token created.".to_string(),
                req_entity.user_id,
                None,
                None,
            )
            .insert(&db)
            .await
            {
                Ok(_) => (),
                Err(err) => error!("{}", err),
            }

            json_response(HttpResponse {
                status: 201,
                message: "Registration token created".to_string(),
                data: Some(registration_token.to_dto()),
            })
        }
        Err(err) => json_response(err.into()),
    }
}
