use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        audit_log::AuditLog,
        http_response::HttpResponse,
        oauth_scope::{OAuthScope, ScopeActions},
    },
    utils::parse_uuid,
};

#[allow(unused)]
#[get("/users/<id>/audit-logs", format = "json")]
pub async fn get_audit_logs_by_user_id(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
) -> Json<HttpResponse<Vec<AuditLog>>> {
    let user_uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return Json(err.into()),
    };

    if !req_entity.is_user()
        && !req_entity
            .token
            .unwrap()
            .check_scope(OAuthScope::AuditLogs(ScopeActions::Read))
        || (req_entity.user.clone().unwrap().id != user_uuid
            && !req_entity.user.unwrap().is_admin())
    {
        return Json(HttpResponse::forbidden("Missing permissions!"));
    }

    match AuditLog::get_by_user_id(user_uuid, &db).await {
        Ok(audit_logs) => Json(HttpResponse::success(
            "Audit Logs found by user id",
            audit_logs,
        )),
        Err(err) => Json(err.into()),
    }
}
