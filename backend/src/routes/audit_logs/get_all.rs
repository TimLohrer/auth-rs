use rocket::http::Status;
use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{audit_log::AuditLog, http_response::HttpResponse},
};

#[allow(unused)]
#[get("/audit-logs", format = "json")]
pub async fn get_all_audit_logs(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
) -> (Status, Json<HttpResponse<Vec<AuditLog>>>) {
    if !req_entity.is_user() || !req_entity.user.unwrap().is_admin() {
        return json_response(HttpResponse::forbidden("Missing permissions!"));
    }

    match AuditLog::get_by_user_id(None, &db).await {
        Ok(audit_logs) => json_response(HttpResponse::success("All Audit Logs", audit_logs)),
        Err(err) => json_response(err.into()),
    }
}
