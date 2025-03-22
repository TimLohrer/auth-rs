use crate::{
    db::{get_main_db, AuthRsDatabase},
    ADMIN_ROLE_ID, DEFAULT_ROLE_ID, SYSTEM_USER_ID,
};
use anyhow::Result;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::{engine::general_purpose, Engine as _};
use mongodb::bson::{doc, DateTime, Uuid};
use rand::Rng;
use rocket::{
    futures::StreamExt,
    serde::{Deserialize, Serialize},
};
use rocket_db_pools::{
    mongodb::{Collection, Database},
    Connection,
};

use super::http_response::HttpResponse;
use super::user_error::{UserError, UserResult};

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
    pub passkeys: Option<String>, // replace this with the actual DTO, this is just a placeholder so the database can already generate the field.
    pub token: String,
    pub roles: Vec<Uuid>,
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
    pub passkeys: bool,
    pub disabled: bool,
    pub created_at: DateTime,
}

impl User {
    pub const COLLECTION_NAME: &'static str = "users";

    pub fn generate_token() -> String {
        // Generate a more secure token using a cryptographically secure RNG
        let mut rng = rand::rng();
        let mut buffer = [0u8; 64]; // 512 bits of randomness
        rng.fill(&mut buffer);

        // Convert to base64 for string representation
        general_purpose::STANDARD.encode(buffer)
    }

    pub fn verify_password(&self, password: &str) -> Result<(), UserError> {
        let hash =
            PasswordHash::new(&self.password_hash).map_err(|_| UserError::PasswordHashingError)?;
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .map_err(|_| UserError::PasswordHashingError)
    }

    pub fn to_dto(&self) -> UserDTO {
        UserDTO {
            id: self.id,
            email: self.email.clone(),
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            roles: self.roles.clone(),
            mfa: self.totp_secret.is_some(),
            passkeys: self.passkeys.is_some(),
            disabled: self.disabled,
            created_at: self.created_at,
        }
    }

    pub fn new(
        email: String,
        password: String,
        first_name: String,
        last_name: String,
    ) -> UserResult<Self> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| UserError::PasswordHashingError)?
            .to_string();

        Ok(Self {
            id: Uuid::new(),
            email,
            first_name,
            last_name,
            password_hash,
            salt: salt.as_str().to_string(),
            totp_secret: None,
            passkeys: None,
            token: Self::generate_token(),
            roles: Vec::from([*DEFAULT_ROLE_ID]),
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
            passkeys: None,
            token: Self::generate_token(),
            roles: roles
                .iter()
                .map(|role| Uuid::parse_str(role).unwrap())
                .collect(),
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
    pub async fn get_full_by_token(token: String, mut db: &Database) -> UserResult<User> {
        let db = db.collection(Self::COLLECTION_NAME);

        let filter = doc! {
            "token": token
        };
        match db.find_one(filter, None).await {
            Ok(Some(user)) => Ok(user),
            //TODO: Not sure if we should return a placeholder UUID here
            Ok(None) => Err(UserError::NotFound(Uuid::new())), // Using a placeholder UUID
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
            Ok(None) => Err(UserError::EmailAlreadyExists(email.to_string())),
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
                "disabled": true
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
    pub async fn delete(
        &self,
        connection: &Connection<AuthRsDatabase>,
    ) -> Result<User, HttpResponse<()>> {
        let db = Self::get_collection(connection);

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
