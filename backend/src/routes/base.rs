
use rocket::{get, serde::json::Json};

use crate::models::http_response::HttpResponse;

#[allow(unused)]
#[get("/", format = "html")]
pub async fn base() -> Json<HttpResponse<String>> {
    Json(HttpResponse {
        status: 200,
        message: "Welcome to the auth-rs API!".to_string(),
        data: None,
    })
}
