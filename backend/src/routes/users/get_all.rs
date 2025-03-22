use rocket::http::Status;
use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

use crate::models::user::UserDTO;
use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{http_response::HttpResponse, user::User},
};

#[allow(unused)]
#[get("/users", format = "json")]
pub async fn get_all_users(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
) -> (Status, Json<HttpResponse<Vec<UserDTO>>>) {
    if !req_entity.is_user() {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    if !req_entity.user.unwrap().is_admin() {
        return json_response(HttpResponse::forbidden("Missing permissions!"));
    }

    //TODO: Add pagination
    match User::get_all(&db).await {
        Ok(users) => json_response(HttpResponse::success(
            "Successfully retrieved all users",
            users.into_iter().map(|user| user.to_dto()).collect(),
        )),
        Err(err) => json_response(err.into()),
    }
}
