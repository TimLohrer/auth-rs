use rocket::http::Status;
use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

use crate::models::user::UserDTO;
use crate::utils::response::json_response;
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
) -> (Status, Json<HttpResponse<UserDTO>>) {
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
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    match User::get_by_id(req_entity.user_id, &db).await {
        Ok(user) => json_response(HttpResponse::success("Found user by id", user.to_dto())),
        Err(err) => json_response(err.into()),
    }
}

#[allow(unused)]
#[get("/users/@me/plain", format = "json")]
pub async fn get_current_user_plain(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
) -> (Status, Option<Json<UserDTO>>) {
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
        return (Status::Unauthorized, None);
    }

    match User::get_by_id(req_entity.user_id, &db).await {
        Ok(user) => (Status::Ok, Some(Json(user.to_dto()))),
        Err(err) => (Status::NotFound, None),
    }
}
