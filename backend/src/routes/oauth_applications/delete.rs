use rocket::http::Status;
use rocket::{delete, error, serde::json::Json};
use rocket_db_pools::Connection;

use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
        oauth_application::OAuthApplication,
    },
    utils::parse_uuid::parse_uuid,
};

#[allow(unused)]
#[delete("/oauth-applications/<id>", format = "json")]
pub async fn delete_oauth_application(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
) -> (Status, Json<HttpResponse<()>>) {
    if !req_entity.is_user() {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };

    let oauth_application = match OAuthApplication::get_full_by_id(uuid, &db).await {
        Ok(oauth_application) => oauth_application,
        Err(err) => return json_response(err.into()),
    };

    if req_entity.user_id != oauth_application.owner && !req_entity.user.unwrap().is_admin() {
        return json_response(HttpResponse::forbidden("Missing permissions!"));
    }

    match oauth_application.delete(&db).await {
        Ok(oauth_application) => {
            match AuditLog::new(
                oauth_application.id,
                AuditLogEntityType::OAuthApplication,
                AuditLogAction::Delete,
                "OAuthApplication deleted.".to_string(),
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

            json_response(HttpResponse::success_no_data("OAuthApplication deleted."))
        }
        Err(err) => json_response(err.into()),
    }
}
