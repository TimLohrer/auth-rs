use std::collections::HashMap;

use super::user_error::{UserError, UserResult};
use super::{
    http_response::HttpResponse, oauth_application::OAuthApplication, oauth_token::OAuthToken,
};
use crate::auth::{AuthEntity, IpAddr};
use crate::models::device::{Device, DeviceDTO};
use crate::models::oauth_scope::{OAuthScope, ScopeActions};
use crate::{
    db::{get_main_db, AuthRsDatabase},
    ADMIN_ROLE_ID, DEFAULT_ROLE_ID, SYSTEM_USER_ID,
};
use anyhow::Result;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use mongodb::bson::{doc, DateTime, Uuid};
use rocket::{
    futures::StreamExt,
    serde::{Deserialize, Serialize},
};
use rocket_db_pools::{
    mongodb::{Collection, Database},
    Connection,
};
use serde_json::Value;
use user_agent_parser::{UserAgent, OS};

pub const MAX_DEVICES: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct User {
    #[serde(rename = "_id")]
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password_hash: String,
    pub salt: String,
    pub totp_secret: Option<String>,
    pub devices: Vec<Device>,
    pub roles: Vec<Uuid>,
    pub data_storage: HashMap<String, Value>,
    pub disabled: bool,
    pub created_at: DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct UserDTO {
    #[serde(rename = "_id")]
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub roles: Vec<Uuid>,
    pub mfa: bool,
    pub devices: Vec<DeviceDTO>,
    pub data_storage: Option<HashMap<String, Value>>,
    pub disabled: bool,
    pub created_at: DateTime,
}

impl User {
    pub const COLLECTION_NAME: &'static str = "users";

    pub fn verify_password(&self, password: &str) -> Result<(), UserError> {
        let hash =
            PasswordHash::new(&self.password_hash).map_err(|_| UserError::PasswordHashingError)?;
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .map_err(|_| UserError::PasswordHashingError)
    }

    pub fn to_dto(&self, include_data_storage: bool) -> UserDTO {
        UserDTO {
            id: self.id,
            email: self.email.clone(),
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            roles: self.roles.clone(),
            mfa: self.totp_secret.is_some(),
            data_storage: if include_data_storage {
                Some(self.data_storage.clone())
            } else {
                None
            },
            devices: self
                .devices
                .iter()
                .map(|device| device.to_dto())
                .collect(),
            disabled: self.disabled,
            created_at: self.created_at,
        }
    }

    pub fn hash_password(password: &str, salt: &str) -> UserResult<String> {
        let salt = SaltString::from_b64(salt).map_err(|_| UserError::PasswordHashingError)?;
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| UserError::PasswordHashingError)?
            .to_string();
        Ok(password_hash)
    }

    pub fn new(
        email: String,
        password: String,
        first_name: String,
        last_name: String,
    ) -> UserResult<Self> {
        let salt = SaltString::generate(&mut OsRng);
        Ok(Self {
            id: Uuid::new(),
            email,
            first_name,
            last_name,
            password_hash: Self::hash_password(&password, &salt.to_string())?,
            salt: salt.as_str().to_string(),
            totp_secret: None,
            devices: vec![],
            roles: Vec::from([*DEFAULT_ROLE_ID]),
            data_storage: HashMap::new(),
            disabled: false,
            created_at: DateTime::now(),
        })
    }

    pub fn new_system(
        id: Uuid,
        email: String,
        password: String,
        first_name: String,
        last_name: String,
        roles: Vec<String>,
    ) -> UserResult<Self> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| UserError::PasswordHashingError)?
            .to_string();

        Ok(Self {
            id,
            email,
            first_name,
            last_name,
            password_hash,
            salt: salt.as_str().to_string(),
            totp_secret: None,
            devices: vec![],
            roles: roles
                .iter()
                .map(|role| Uuid::parse_str(role).unwrap())
                .collect(),
            data_storage: HashMap::new(),
            disabled: false,
            created_at: DateTime::now(),
        })
    }

    #[allow(unused)]
    pub fn is_admin(&self) -> bool {
        self.id == *SYSTEM_USER_ID || self.roles.contains(&*ADMIN_ROLE_ID)
    }

    #[allow(unused)]
    pub fn is_system_admin(&self) -> bool {
        self.id == *SYSTEM_USER_ID
    }

    #[allow(unused)]
    pub fn can_read_full_data_storage(req_entity: AuthEntity, user_id: &Uuid) -> bool {
        (req_entity.is_user() && (&req_entity.user.clone().unwrap().id == user_id
            || req_entity.user.as_ref().map_or(false, |u| u.is_admin())))
            || req_entity
                .token
                .as_ref()
                .unwrap()
                .check_scope(OAuthScope::UserDataStorage(ScopeActions::All))
    }

    #[allow(unused)]
    pub fn can_read_data_storage_key(req_entity: AuthEntity, user_id: &Uuid) -> bool {
        (req_entity.is_user() && (&req_entity.user.clone().unwrap().id == user_id
            || req_entity.user.as_ref().map_or(false, |u| u.is_admin())))
            || (req_entity
                .token
                .as_ref()
                .unwrap()
                .check_scope(OAuthScope::UserDataStorage(ScopeActions::Read))
                || req_entity
                    .token
                    .as_ref()
                    .unwrap()
                    .check_scope(OAuthScope::UserDataStorage(ScopeActions::All)))
    }


    #[allow(unused)]
    pub fn can_update_data_storage_key(req_entity: AuthEntity, user_id: &Uuid) -> bool {
        (req_entity.is_user() && (&req_entity.user.clone().unwrap().id == user_id
            || req_entity.user.as_ref().map_or(false, |u| u.is_admin())))
            || (req_entity
                .token
                .as_ref()
                .unwrap()
                .check_scope(OAuthScope::UserDataStorage(ScopeActions::Update))
                || req_entity
                    .token
                    .as_ref()
                    .unwrap()
                    .check_scope(OAuthScope::UserDataStorage(ScopeActions::All)))
    }

    #[allow(unused)]
    pub fn can_delete_data_storage_key(req_entity: AuthEntity, user_id: &Uuid) -> bool {
        (req_entity.is_user() && (&req_entity.user.clone().unwrap().id == user_id
            || req_entity.user.as_ref().map_or(false, |u| u.is_admin())))
            || (req_entity
                .token
                .as_ref()
                .unwrap()
                .check_scope(OAuthScope::UserDataStorage(ScopeActions::Delete))
                || req_entity
                    .token
                    .as_ref()
                    .unwrap()
                    .check_scope(OAuthScope::UserDataStorage(ScopeActions::All)))
    }

    #[allow(unused)]
    pub async fn get_full_by_id(
        id: Uuid,
        connection: &Connection<AuthRsDatabase>,
    ) -> UserResult<User> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": id
        };
        match db.find_one(filter, None).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(UserError::NotFound(id)),
            Err(err) => Err(UserError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn get_by_id(id: Uuid, connection: &Connection<AuthRsDatabase>) -> UserResult<User> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": id
        };
        match db.find_one(filter, None).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(UserError::NotFound(id)),
            Err(err) => Err(UserError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn get_by_id_db_param(id: Uuid, mut db: &Database) -> UserResult<User> {
        let db = db.collection(Self::COLLECTION_NAME);

        let filter = doc! {
            "_id": id
        };
        match db.find_one(filter, None).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(UserError::NotFound(id)),
            Err(err) => Err(UserError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn get_by_email(
        email: &str,
        connection: &Connection<AuthRsDatabase>,
    ) -> UserResult<User> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "email": email.to_lowercase()
        };
        match db.find_one(filter, None).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(UserError::InvalidEmail),
            Err(err) => Err(UserError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn get_all(connection: &Connection<AuthRsDatabase>) -> UserResult<Vec<User>> {
        let db = Self::get_collection(connection);

        match db.find(None, None).await {
            Ok(cursor) => {
                let users = cursor
                    .map(|doc| {
                        let user: User = doc.unwrap();
                        user
                    })
                    .collect::<Vec<User>>()
                    .await;
                Ok(users)
            }
            Err(err) => Err(UserError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn insert(&self, connection: &Connection<AuthRsDatabase>) -> UserResult<User> {
        let db = Self::get_collection(connection);

        match db.insert_one(self.clone(), None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(UserError::DatabaseError(format!(
                "Error inserting user: {}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn update(&self, connection: &Connection<AuthRsDatabase>) -> UserResult<User> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": self.id
        };
        match db.replace_one(filter, self.clone(), None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(UserError::DatabaseError(format!(
                "Error updating user: {}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn remove_role_from_all(
        role_id: Uuid,
        connection: &Connection<AuthRsDatabase>,
    ) -> Result<(), UserError> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "roles": {
                "$in": [role_id]
            }
        };
        let update = doc! {
            "$pull": {
                "roles": role_id
            }
        };
        match db.update_many(filter, update, None).await {
            Ok(_) => Ok(()),
            Err(err) => Err(UserError::DatabaseError(format!(
                "Error removing role from all users: {}",
                err
            ))),
        }
    }

    #[allow(unused)]
    pub async fn disable(
        &self,
        connection: &Connection<AuthRsDatabase>,
    ) -> Result<(), HttpResponse<()>> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": self.id
        };
        let update = doc! {
            "$set": {
                "disabled": true,
                "devices": []
            }
        };
        match db.find_one_and_update(filter, update, None).await {
            Ok(_) => Ok(()),
            Err(err) => Err(HttpResponse {
                status: 500,
                message: format!("Error disabeling user: {:?}", err),
                data: None,
            }),
        }
    }

    #[allow(unused)]
    pub fn get_data_storage_by_key(&self, key: &str) -> Option<Value> {
        self.data_storage.get(key).cloned()
    }

    #[allow(unused)]
    pub async fn update_data_storage_key(&mut self, connection: &Connection<AuthRsDatabase>, key: &str, value: Value) -> Result<(), HttpResponse<()>> {
        self.data_storage.insert(key.to_string(), value);
        self.update(connection).await?;
        Ok(())
    }

    #[allow(unused)]
    pub async fn delete_data_storage_key(&mut self, connection: &Connection<AuthRsDatabase>, key: &str) -> Result<(), HttpResponse<()>> {
        self.data_storage.remove(key);
        self.update(connection).await?;
        Ok(())
    }

    #[allow(unused)]
    pub async fn enable(
        &self,
        connection: &Connection<AuthRsDatabase>,
    ) -> Result<(), HttpResponse<()>> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": self.id
        };
        let update = doc! {
            "$set": {
                "disabled": false
            }
        };
        match db.find_one_and_update(filter, update, None).await {
            Ok(_) => Ok(()),
            Err(err) => Err(HttpResponse {
                status: 500,
                message: format!("Error enabeling user: {:?}", err),
                data: None,
            }),
        }
    }

    #[allow(unused)]
    pub async fn get_device(&self,
        connection: &Connection<AuthRsDatabase>,
        os: OS<'_>,
        user_agent: UserAgent<'_>,
        ip: IpAddr
    ) -> Result<Device, UserError> {
        let db = Self::get_collection(connection);

        let os = os.name.unwrap_or_default().into_owned();
        let user_agent = user_agent.user_agent.unwrap_or_default().into_owned();
        let ip = ip.addr.unwrap_or_default();
        
        let filter = doc! {
            "_id": self.id.clone()
        };

        match db.find_one(filter.clone(), None).await {
            Ok(Some(mut user)) => {
                for device in user.devices.clone() {
                    if (device.os.to_uppercase() == "UNKNOWN" || device.os == os)
                        && device.user_agent == user_agent
                        && (device.ip_address.to_uppercase() == "UNKNOWN" || device.ip_address == ip)
                    {
                        return Ok(device);
                    }
                }
                
                if user.devices.len() >= MAX_DEVICES {
                    return Err(UserError::MaxDevicesReached);
                }

                let device = Device::new(self.id.clone(), if os.is_empty() { None } else { Some(os) }, user_agent, if ip.is_empty() { None } else { Some(ip) });
                user.devices.push(device.clone());
                db.replace_one(filter, user, None).await.map_err(|err| UserError::DatabaseError(err.to_string()))?;
                Ok(device)
            },
            Ok(None) => Err(UserError::NotFound(Uuid::new())),
            Err(err) => Err(UserError::DatabaseError(err.to_string())),
        }
    }

    #[allow(unused)]
    pub async fn cleanup_expired_devices(
        &self,
        connection: &Connection<AuthRsDatabase>,
    ) -> Result<(), UserError> {
        let db = Self::get_collection(connection);

        for device in &self.devices {
            match verify_id_token(&device.token) {
                Ok(_) => {},
                Err(_) => {
                    let _ = self.remove_device(device.id, connection).await;
                },
            }
        }

        Ok(())
    }

    #[allow(unused)]
    pub async fn delete(
        &self,
        connection: &Connection<AuthRsDatabase>,
    ) -> Result<User, HttpResponse<()>> {
        let db = Self::get_collection(connection);

        // Delete all owned OAuth applications
        OAuthApplication::delete_all_matching(doc! { "owner": self.id }, connection)
            .await
            .map_err(|err| {
                UserError::DatabaseError(format!("Error deleting owned oauth apps data: {:?}", err))
            })?;

        // Delete all OAuth tokens that belong to this user
        OAuthToken::delete_all_matching(doc! { "userId": self.id }, connection)
            .await
            .map_err(|err| UserError::DatabaseError(err.to_string()))?;

        let filter = doc! {
            "_id": self.id
        };
        match db.delete_one(filter, None).await {
            Ok(_) => Ok(self.clone()),
            Err(err) => Err(HttpResponse {
                status: 500,
                message: format!("Error deleting user: {:?}", err),
                data: None,
            }),
        }
    }

    #[allow(unused)]
    fn get_collection(connection: &Connection<AuthRsDatabase>) -> Collection<Self> {
        let db = get_main_db(connection);
        db.collection(Self::COLLECTION_NAME)
    }
}
