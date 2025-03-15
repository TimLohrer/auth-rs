use rocket::{delete, error, serde::json::Json};
use rocket_db_pools::Connection;

use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
        user::User,
    },
    utils::parse_uuid,
};

#[allow(unused)]
#[delete("/users/<id>", format = "json")]
pub async fn delete_user(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
) -> Json<HttpResponse<()>> {
    if !req_entity.is_user() {
        return Json(HttpResponse::forbidden("Forbidden"));
    }

    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return Json(err.into()),
    };

    if req_entity.user_id != uuid && !req_entity.user.unwrap().is_system_admin() {
        return Json(HttpResponse::forbidden("Missing permissions!"));
    }

    let user = match User::get_full_by_id(uuid, &db).await {
        Ok(user) => user,
        Err(err) => {
            return Json(HttpResponse::not_found(&format!(
                "User does not exist: {:?}",
                err
            )))
        }
    };

    match user.delete(&db).await {
        Ok(user) => {
            match AuditLog::new(
                user.id,
                AuditLogEntityType::User,
                AuditLogAction::Delete,
                "User deleted.".to_string(),
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

            Json(HttpResponse::success_no_data("User deleted"))
        }
        Err(err) => Json(err),
    }
}
