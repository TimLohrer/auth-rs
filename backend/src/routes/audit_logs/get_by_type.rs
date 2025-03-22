use rocket::http::Status;
use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        audit_log::{AuditLog, AuditLogEntityType},
        http_response::HttpResponse,
    },
};

#[allow(unused)]
#[get("/audit-logs/<type>", format = "json")]
pub async fn get_audit_logs_by_type(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    r#type: &str,
) -> (Status, Json<HttpResponse<Vec<AuditLog>>>) {
    if !req_entity.is_user() || !req_entity.user.unwrap().is_admin() {
        return json_response(HttpResponse::forbidden("Missing permissions!"));
    }

    let entity_type = match AuditLogEntityType::from_string(r#type) {
        Ok(entity_type) => Some(entity_type),
        Err(err) => return json_response(err.into()),
    };

    match AuditLog::get_all_from_type(entity_type.unwrap(), &db).await {
        Ok(audit_logs) => json_response(HttpResponse::success(
            "Successfully retrieved all audit logs by type",
            audit_logs,
        )),
        Err(err) => json_response(err.into()),
    }
}
