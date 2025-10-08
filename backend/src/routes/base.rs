use std::collections::HashMap;
use dotenv::var;
use rocket::{get, serde::json::Json};

use crate::models::http_response::HttpResponse;

#[allow(unused)]
#[get("/")]
pub async fn base() -> Json<HttpResponse<HashMap<String, String>>> {
    Json(HttpResponse {
        status: 200,
        message: "Welcome to the auth-rs API!".to_string(),
        data: Some(HashMap::from_iter(vec![
            (
                "version".to_string(),
                var("VERSION").expect("Missing VERSION in .env!"),
            ),
            (
                "repository".to_string(),
                "https://github.com/TimLohrer/auth-rs".to_string(),
            ),
            (
                "issues".to_string(),
                "https://github.com/TimLohrer/auth-rs/issues".to_string(),
            ),
        ]))
    })
}