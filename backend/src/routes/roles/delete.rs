use rocket::http::Status;
use rocket::{delete, error, serde::json::Json};
use rocket_db_pools::Connection;

use crate::utils::parse_uuid::parse_uuid;
use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
        role::Role,
    },
};

#[allow(unused)]
#[delete("/roles/<id>", format = "json")]
pub async fn delete_role(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
) -> (Status, Json<HttpResponse<()>>) {
    if !req_entity.is_user() {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    if !req_entity.user.unwrap().is_admin() {
        return json_response(HttpResponse::forbidden("Missing permissions!"));
    }

    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => {
            return json_response(err.into());
        }
    };

    let role = match Role::get_by_id(uuid, &db).await {
        Ok(role) => role,
        Err(err) => {
            return json_response(HttpResponse::not_found(&format!(
                "Role does not exist: {:?}",
                err
            )))
        }
    };

    if role.system {
        return json_response(HttpResponse::bad_request("Cannot delete system role"));
    }

    match role.delete(&db).await {
        Ok(role) => {
            match AuditLog::new(
                role.id,
                AuditLogEntityType::Role,
                AuditLogAction::Delete,
                "Role deleted.".to_string(),
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

            json_response(HttpResponse::success_no_data("Role deleted"))
        }
        Err(err) => json_response(err.into()),
    }
}
