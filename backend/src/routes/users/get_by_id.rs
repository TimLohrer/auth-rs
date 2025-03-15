use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

use crate::models::user::UserDTO;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        http_response::HttpResponse,
        oauth_scope::{OAuthScope, ScopeActions},
        user::User,
    },
    utils::parse_uuid,
};

#[allow(unused)]
#[get("/users/<id>", format = "json")]
pub async fn get_user_by_id(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
) -> Json<HttpResponse<UserDTO>> {
    if req_entity.is_token()
        && (!req_entity
            .token
            .as_ref()
            .unwrap()
            .check_scope(OAuthScope::Users(ScopeActions::Read))
            || req_entity
                .token
                .as_ref()
                .unwrap()
                .check_scope(OAuthScope::Users(ScopeActions::All)))
    {
        return Json(HttpResponse::forbidden("Forbidden"));
    }

    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return Json(err.into()),
    };

    if (req_entity.is_user()
        && req_entity.user_id != uuid
        && !req_entity.user.as_ref().unwrap().is_admin())
        || req_entity.is_token() && req_entity.user_id != uuid
    {
        return Json(HttpResponse::forbidden("Missing permissions!"));
    }

    match User::get_by_id(uuid, &db).await {
        Ok(user) => Json(HttpResponse::success("Found user by id", user.to_dto())),
        Err(err) => Json(err.into()),
    }
}
