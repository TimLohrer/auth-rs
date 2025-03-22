use crate::models::http_response::HttpResponse;
use rocket::http::Status;
use rocket::serde::json::Json;

pub fn json_response<T>(response: HttpResponse<T>) -> (Status, Json<HttpResponse<T>>) {
    let status = match response.status {
        200 => Status::Ok,
        201 => Status::Created,
        400 => Status::BadRequest,
        401 => Status::Unauthorized,
        403 => Status::Forbidden,
        404 => Status::NotFound,
        500 => Status::InternalServerError,
        _ => Status::InternalServerError,
    };
    (status, Json(response))
}
