use rocket::http::Status;
use rocket::{delete, error, serde::json::Json};
use rocket_db_pools::Connection;

use crate::models::registration_token::RegistrationToken;
use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
    },
    utils::parse_uuid::parse_uuid,
};

#[allow(unused)]
#[delete("/registration-tokens/<id>", format = "json")]
pub async fn delete_registration_token(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
) -> (Status, Json<HttpResponse<()>>) {
    if !req_entity.is_user() || !req_entity.user.unwrap().is_admin() {
        return json_response(HttpResponse::forbidden(
            "Only admins can delete registration tokens",
        ));
    }

    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };

    let registration_token = match RegistrationToken::get_by_id(uuid, &db).await {
        Ok(registration_token) => registration_token,
        Err(err) => return json_response(err.into()),
    };

    match registration_token.delete(&db).await {
        Ok(registration_token) => {
            match AuditLog::new(
                registration_token.id.to_string(),
                AuditLogEntityType::RegistrationToken,
                AuditLogAction::Delete,
                "Registration token deleted.".to_string(),
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

            json_response(HttpResponse::success_no_data("Registration token deleted."))
        }
        Err(err) => json_response(err.into()),
    }
}
