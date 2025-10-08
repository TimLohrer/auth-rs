use std::collections::HashMap;

use rocket::http::Status;
use rocket::{put, delete, serde::{json::Json, Deserialize}};
use rocket_db_pools::Connection;
use serde_json::Value;

use crate::utils::parse_uuid::parse_uuid;
use crate::utils::response::json_response;
use crate::{
    auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        http_response::HttpResponse,
        user::User,
    },
};

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct UpdateStorageRequest {
    data: Value
}

#[allow(unused)]
#[put("/users/<id>/data-storage/<key>", format = "json", data = "<data>")]
pub async fn update_user_data_storage_key(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    key: &str,
    data: Json<UpdateStorageRequest>,
) -> (Status, Json<HttpResponse<HashMap<String, Value>>>) {
    let value = data.into_inner().data;

    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };

    if User::can_read_data_storage_key(req_entity.clone(), &req_entity.user_id) {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    match User::get_by_id(req_entity.user_id, &db).await {
        Ok(mut user) => {
            match user.update_data_storage_key(&db, key, value.clone()).await {
                Ok(_) => json_response(HttpResponse::success("Updated user storage key", HashMap::from([(key.to_string(), value)]))),
                Err(_) => json_response(HttpResponse::internal_error("Failed to update user storage key")),
            }
        },
        Err(err) => json_response(err.into()),
    }
}

#[allow(unused)]
#[delete("/users/<id>/data-storage/<key>", format = "json")]
pub async fn delete_user_data_storage_key(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    key: &str,
) -> (Status, Json<HttpResponse<Value>>) {
    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };

    if User::can_delete_data_storage_key(req_entity.clone(), &req_entity.user_id) {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    match User::get_by_id(req_entity.user_id, &db).await {
        Ok(mut user) => {
            match user.get_data_storage_by_key(key) {
                Some(value) => {
                    match user.delete_data_storage_key(&db, key).await {
                        Ok(_) => json_response(HttpResponse::success("Deleted user storage key", value)),
                        Err(_) => json_response(HttpResponse::internal_error("Failed to delete user storage key")),
                    }
                },
                None => json_response(HttpResponse::not_found("Key not found")),
            }
        },
        Err(err) => json_response(err.into()),
    }
}