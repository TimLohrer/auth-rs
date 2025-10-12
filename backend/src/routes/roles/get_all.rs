use rocket::http::Status;
use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

use crate::utils::response::json_response;
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
) -> (Status, Json<HttpResponse<Vec<Role>>>) {
    if !req_entity.is_user() {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    match Role::get_all(&db, None).await {
        Ok(roles) => json_response(HttpResponse {
            status: 200,
            message: "Successfully retrieved all roles".to_string(),
            data: Some(roles),
        }),
        Err(err) => json_response(err.into()),
    }
}
