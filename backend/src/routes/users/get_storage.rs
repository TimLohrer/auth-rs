use std::collections::HashMap;

use rocket::http::Status;
use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;
use serde_json::Value;

use crate::utils::parse_uuid::parse_uuid;
use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        http_response::HttpResponse,
        user::User,
    },
};

#[allow(unused)]
#[get("/users/<id>/full-data-storage", format = "json")]
pub async fn get_full_user_data_storage(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
) -> (Status, Json<HttpResponse<HashMap<String, HashMap<String, Value>>>>) {
    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };

    if !req_entity.is_user() || (req_entity.user.as_ref().unwrap().id != uuid && !req_entity.user.as_ref().unwrap().is_admin()) {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    match User::get_by_id(uuid, &db).await {
        Ok(user) => json_response(HttpResponse::success("Found full user storage by id", user.data_storage)),
        Err(err) => json_response(err.into()),
    }
}

#[allow(unused)]
#[get("/users/<id>/data-storage", format = "json")]
pub async fn get_user_data_storage(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
) -> (Status, Json<HttpResponse<HashMap<String, Value>>>) {
    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };

    if !User::can_read_full_data_storage(req_entity.clone(), &uuid) {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    let sandbox_id = if req_entity.is_token() {
        req_entity.token.as_ref().unwrap().id
    } else {
        req_entity.user_id
    }.to_string();

    match User::get_by_id(uuid, &db).await {
        Ok(user) => json_response(HttpResponse::success("Found user storage by id", user.data_storage.get(&sandbox_id).cloned().unwrap_or_default())),
        Err(err) => json_response(err.into()),
    }
}

#[allow(unused)]
#[get("/users/<id>/data-storage/<key>", format = "json")]
pub async fn get_user_data_storage_key(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    key: &str,
) -> (Status, Json<HttpResponse<Value>>) {
    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };

    if !User::can_read_data_storage_key(req_entity.clone(), &uuid) {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    let sandbox_id = if req_entity.is_token() {
        req_entity.token.as_ref().unwrap().id
    } else {
        req_entity.user_id
    }.to_string();

    match User::get_by_id(uuid, &db).await {
        Ok(user) => {
            match user.get_data_storage_by_key(&sandbox_id, key) {
                Some(value) => json_response(HttpResponse::success("Found user storage key", value.clone())),
                None => json_response(HttpResponse::not_found("Key not found")),
            }
        },
        Err(err) => json_response(err.into()),
    }
}