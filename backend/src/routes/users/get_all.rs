use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

use crate::models::user::UserDTO;
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
) -> Json<HttpResponse<Vec<UserDTO>>> {
    if !req_entity.is_user() {
        return Json(HttpResponse::forbidden("Forbidden"));
    }

    if !req_entity.user.unwrap().is_admin() {
        return Json(HttpResponse::forbidden("Missing permissions!"));
    }

    //TODO: Add pagination
    match User::get_all(&db).await {
        Ok(users) => Json(HttpResponse::success(
            "Successfully retrieved all users",
            users.into_iter().map(|user| user.to_dto()).collect(),
        )),
        Err(err) => Json(err.into()),
    }
}
