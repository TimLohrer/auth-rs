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
};

#[allow(unused)]
#[get("/users/@me", format = "json")]
pub async fn get_current_user(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
) -> Json<HttpResponse<UserDTO>> {
    if req_entity.is_token()
        && (!req_entity
            .token
            .as_ref()
            .unwrap()
            .check_scope(OAuthScope::Users(ScopeActions::Read))
            || req_entity
                .token
                .clone()
                .unwrap()
                .check_scope(OAuthScope::Users(ScopeActions::All)))
    {
        return Json(HttpResponse::forbidden("Forbidden"));
    }

    match User::get_by_id(req_entity.user_id, &db).await {
        Ok(user) => Json(HttpResponse::success("Found user by id", user.to_dto())),
        Err(err) => Json(err.into()),
    }
}

#[allow(unused)]
#[get("/users/@me/plain", format = "json")]
pub async fn get_current_user_plain(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
) -> Option<Json<UserDTO>> {
    if req_entity.is_token()
        && (!req_entity
            .token
            .clone()
            .unwrap()
            .check_scope(OAuthScope::Users(ScopeActions::Read))
            || req_entity
                .token
                .clone()
                .unwrap()
                .check_scope(OAuthScope::Users(ScopeActions::All)))
    {
        return None;
    }

    match User::get_by_id(req_entity.user_id, &db).await {
        Ok(user) => Some(Json(user.to_dto())),
        Err(err) => None,
    }
}
