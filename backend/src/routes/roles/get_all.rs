use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{http_response::HttpResponse, role::Role},
};

#[allow(unused)]
#[get("/roles", format = "json")]
pub async fn get_all_roles(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
) -> Json<HttpResponse<Vec<Role>>> {
    if !req_entity.is_user() {
        return Json(HttpResponse::forbidden("Forbidden"));
    }

    match Role::get_all(&db, None).await {
        Ok(roles) => Json(HttpResponse {
            status: 200,
            message: "Successfully retrieved all roles".to_string(),
            data: Some(roles),
        }),
        Err(err) => Json(err.into()),
    }
}
