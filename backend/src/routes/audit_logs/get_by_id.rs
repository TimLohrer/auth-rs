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
    utils::parse_uuid::parse_uuid,
};

#[allow(unused)]
#[get("/audit-logs/<type>/id/<id>", format = "json")]
pub async fn get_audit_log_by_id(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    r#type: &str,
    id: &str,
) -> (Status, Json<HttpResponse<AuditLog>>) {
    if !req_entity.is_user() {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };

    if req_entity.user_id != uuid && !req_entity.user.unwrap().is_admin() {
        return json_response(HttpResponse::forbidden("Missing permissions!"));
    }

    let entity_type = match AuditLogEntityType::from_string(r#type) {
        Ok(entity_type) => entity_type,
        Err(err) => return json_response(err.into()),
    };

    match AuditLog::get_by_id(uuid, entity_type, &db).await {
        Ok(audit_log) => json_response(HttpResponse::success("Audit Log found by id", audit_log)),
        Err(err) => json_response(err.into()),
    }
}
