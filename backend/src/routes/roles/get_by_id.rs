use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

use crate::utils::parse_uuid;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        http_response::HttpResponse,
        oauth_scope::{OAuthScope, ScopeActions},
        role::Role,
    },
};

#[allow(unused)]
#[get("/roles/<id>", format = "json")]
pub async fn get_role_by_id(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
) -> Json<HttpResponse<Role>> {
    if !req_entity.is_token() {
        return Json(HttpResponse::bad_request("Missing token"));
    }

    //TODO: Should this only fail if BOTH are not there or if either is not there?
    if !req_entity
        .token
        .as_ref()
        .unwrap()
        .check_scope(OAuthScope::Roles(ScopeActions::Read))
        && !req_entity
            .token
            .unwrap()
            .check_scope(OAuthScope::Roles(ScopeActions::All))
    {
        return Json(HttpResponse::forbidden("Forbidden"));
    }

    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return Json(err.into()),
    };

    match Role::get_by_id(uuid, &db).await {
        Ok(role) => Json(HttpResponse::success("Found role by id", role)),
        Err(err) => Json(err.into()),
    }
}
