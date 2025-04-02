use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;
use mongodb::bson::Uuid;
use rocket::{
    http::Status,
    post,
    serde::{json::Json, Deserialize, Serialize},
};
use rocket_db_pools::Connection;
use url::Url;
use webauthn_rs::{
    proto::{
        RegisterPublicKeyCredential, PublicKeyCredential,
        CreationChallengeResponse, RequestChallengeResponse,
        Credential, COSEKey, UserVerificationPolicy,
    },
    AuthenticationState, RegistrationState, Webauthn,
};
use base64::{engine::general_purpose, Engine as _};

use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    errors::{ApiError, ApiResult, AppError},
    models::{
        http_response::HttpResponse,
        user::{User, UserDTO},
        passkey::Passkey,
    },
    utils::response::json_response,
};

// In-memory storage for registration and authentication sessions
lazy_static! {
    static ref REGISTRATIONS: Mutex<HashMap<Uuid, (Uuid, RegistrationState)>> = Mutex::new(HashMap::new());
    static ref AUTHENTICATIONS: Mutex<HashMap<Uuid, (Vec<Uuid>, AuthenticationState)>> = Mutex::new(HashMap::new());
}

// Define WebauthnConfig outside of the function
struct WebauthnConfig {
    rp_name: String,
    rp_id: String,
    rp_origin: Url,
}

impl webauthn_rs::WebauthnConfig for WebauthnConfig {
    fn get_relying_party_name(&self) -> &str {
        &self.rp_name
    }

    fn get_origin(&self) -> &Url {
        &self.rp_origin
    }

    fn get_relying_party_id(&self) -> &str {
        &self.rp_id
    }
}

//TODO: First create a config file for these values, secondly check if this needs to be instantiated every time or if it can be a static variable
// Initialize Webauthn instance
fn get_webauthn() -> Webauthn<WebauthnConfig> {
    let rp_id = "localhost"; // Should match your domain
    let rp_origin = Url::parse(&format!("http://{}", rp_id)).expect("Invalid URL");
    
    let config = WebauthnConfig {
        rp_name: "auth-rs".to_string(),
        rp_id: rp_id.to_string(),
        rp_origin,
    };
    
    Webauthn::new(config)
}

// DTO for passkey registration request
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegisterStartRequest {
    pub user_id: Uuid,
}

// DTO for passkey registration finish request
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegisterFinishRequest {
    pub registration_id: Uuid,
    pub credential: RegisterPublicKeyCredential,
}

// DTO for passkey authentication start request
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthenticateStartRequest {
    pub email: String,
}

// DTO for passkey authentication finish request
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthenticateFinishRequest {
    pub authentication_id: Uuid,
    pub credential: PublicKeyCredential,
}

// Response for passkey registration start
#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegisterStartResponse {
    pub challenge: String,
    pub registration_id: Uuid,
    pub public_key: CreationChallengeResponse,
}

// Response for passkey registration finish
#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegisterFinishResponse {
    pub id: Uuid,
    pub device_type: String,
    pub created_at: mongodb::bson::DateTime,
}

// Response for passkey authentication start
#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthenticateStartResponse {
    pub challenge: String,
    pub authentication_id: Uuid,
    pub public_key: RequestChallengeResponse,
}

// Response for passkey authentication finish
#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthenticateFinishResponse {
    pub user: UserDTO,
    pub token: String,
}

// 1. Register Passkey - Start Registration
#[post("/auth/passkeys/register/start", format = "json", data = "<data>")]
pub async fn register_start(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    data: Json<PasskeyRegisterStartRequest>,
) -> (Status, Json<HttpResponse<PasskeyRegisterStartResponse>>) {
    match process_register_start(db, req_entity, data.into_inner()).await {
        Ok(response) => json_response(HttpResponse {
            status: 200,
            message: "Passkey registration initiated".to_string(),
            data: Some(response),
        }),
        Err(err) => json_response(err.into()),
    }
}

async fn process_register_start(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    data: PasskeyRegisterStartRequest,
) -> ApiResult<PasskeyRegisterStartResponse> {
    // Verify that the user ID in the request matches the authenticated user's ID
    if data.user_id != req_entity.user_id {
        return Err(ApiError::Unauthorized("Cannot register passkey for another user".to_string()));
    }
    
    // Find the user
    let user = User::get_by_id(data.user_id, &db).await
        .map_err(|e| ApiError::NotFound(format!("User not found: {}", e)))?;
    
    // Initialize Webauthn
    let webauthn = get_webauthn();
    
    // Generate challenge for registration
    let (challenge, reg_state) = webauthn.generate_challenge_register(&user.email, false)
        .map_err(|e| ApiError::AppError(AppError::WebauthnError(e)))?;
    
    // Store registration state
    let registration_id = Uuid::new();
    REGISTRATIONS.lock().unwrap().insert(registration_id, (data.user_id, reg_state));
    
    // Create response
    let challenge_b64 = general_purpose::STANDARD.encode(&challenge.public_key.challenge);
    
    Ok(PasskeyRegisterStartResponse {
        challenge: challenge_b64,
        registration_id,
        public_key: challenge,
    })
}

// 2. Finish Passkey Registration
#[post("/auth/passkeys/register/finish", format = "json", data = "<data>")]
pub async fn register_finish(
    db: Connection<AuthRsDatabase>,
    data: Json<PasskeyRegisterFinishRequest>,
) -> (Status, Json<HttpResponse<PasskeyRegisterFinishResponse>>) {
    match process_register_finish(db, data.into_inner()).await {
        Ok(response) => json_response(HttpResponse {
            status: 200,
            message: "Passkey registered successfully".to_string(),
            data: Some(response),
        }),
        Err(err) => json_response(err.into()),
    }
}

async fn process_register_finish(
    db: Connection<AuthRsDatabase>,
    data: PasskeyRegisterFinishRequest,
) -> ApiResult<PasskeyRegisterFinishResponse> {
    // Get the registration state
    let (user_id, reg_state) = REGISTRATIONS.lock().unwrap()
        .remove(&data.registration_id)
        .ok_or(ApiError::InvalidState("Registration not found".to_string()))?;
    
    // Initialize Webauthn
    let webauthn = get_webauthn();
    
    // Function to check if credential exists
    let cred_exists_fn = |_: &Vec<u8>| -> Result<bool, ()> { Ok(false) };
    
    // Verify and process registration
    let result = webauthn.register_credential(
        &data.credential,
        &reg_state,
        cred_exists_fn,
    ).map_err(|e| ApiError::AppError(AppError::WebauthnError(e)))?;
    
    // Extract credential ID for storage
    let credential_id = general_purpose::STANDARD.encode(&result.0.cred_id);
    
    // Create our passkey model
    let mut passkey = Passkey::new(
        credential_id.clone().into_bytes(),
        serde_json::to_string(&result.0)
            .map_err(|e| ApiError::AppError(AppError::JsonSerializationError(e)))?,
        result.1.counter,
    );
    
    // Find the user
    let mut user = User::get_by_id(user_id, &db).await
        .map_err(|_| ApiError::NotFound("User not found".to_string()))?;
    
    // Set device type
    passkey.device_type = "passkey".to_string();
    
    // Add passkey to user and update
    user.add_passkey(passkey.clone());
    user.update(&db).await
        .map_err(|e| ApiError::AppError(AppError::DatabaseError(e.to_string())))?;
    
    // Return success response
    Ok(PasskeyRegisterFinishResponse {
        id: passkey.id,
        device_type: passkey.device_type,
        created_at: passkey.created_at,
    })
}

// 3. Start Passkey Authentication
#[post("/auth/passkeys/authenticate/start", format = "json", data = "<data>")]
pub async fn authenticate_start(
    db: Connection<AuthRsDatabase>,
    data: Json<PasskeyAuthenticateStartRequest>,
) -> (Status, Json<HttpResponse<PasskeyAuthenticateStartResponse>>) {
    match process_authenticate_start(db, data.into_inner()).await {
        Ok(response) => json_response(HttpResponse {
            status: 200,
            message: "Authentication initiated".to_string(),
            data: Some(response),
        }),
        Err(err) => json_response(err.into()),
    }
}

async fn process_authenticate_start(
    db: Connection<AuthRsDatabase>,
    data: PasskeyAuthenticateStartRequest,
) -> ApiResult<PasskeyAuthenticateStartResponse> {
    // Find the user by email
    let user = User::get_by_email(&data.email, &db).await
        .map_err(|e| ApiError::NotFound(format!("User not found: {}", e)))?;
    
    // Check if user has passkeys
    if user.passkeys.is_empty() {
        return Err(ApiError::InvalidState("User has no passkeys registered".to_string()));
    }
    
    // Get credentials from passkeys
    let credentials = user.passkeys.iter()
        .map(|pk| {
            let cred_bytes = pk.get_credential_id_bytes()
                .map_err(|e| ApiError::AppError(AppError::InvalidState(e.to_string())))?;
            
            // Parse the COSEKey from the stored JSON
            let cose_key: COSEKey = serde_json::from_str(&pk.public_key)
                .map_err(|e| ApiError::AppError(AppError::JsonSerializationError(e)))?;
                
            Ok(Credential {
                cred_id: cred_bytes,
                cred: cose_key,
                counter: pk.counter,
                verified: true,
                registration_policy: UserVerificationPolicy::Required,
            })
        })
        .collect::<ApiResult<Vec<_>>>()?;
    
    // Initialize Webauthn
    let webauthn = get_webauthn();
    
    // Generate challenge for authentication
    let (challenge, auth_state) = webauthn.generate_challenge_authenticate(credentials)
        .map_err(|e| ApiError::AppError(AppError::WebauthnError(e)))?;
    
    // Store authentication state
    let authentication_id = Uuid::new();
    AUTHENTICATIONS.lock().unwrap().insert(authentication_id, (vec![user.id], auth_state));
    
    // Create response
    let challenge_b64 = general_purpose::STANDARD.encode(&challenge.public_key.challenge);
    
    Ok(PasskeyAuthenticateStartResponse {
        challenge: challenge_b64,
        authentication_id,
        public_key: challenge,
    })
}

// 4. Finish Passkey Authentication
#[post("/auth/passkeys/authenticate/finish", format = "json", data = "<data>")]
pub async fn authenticate_finish(
    db: Connection<AuthRsDatabase>,
    data: Json<PasskeyAuthenticateFinishRequest>,
) -> (Status, Json<HttpResponse<PasskeyAuthenticateFinishResponse>>) {
    match process_authenticate_finish(db, data.into_inner()).await {
        Ok(response) => json_response(HttpResponse {
            status: 200,
            message: "Authentication successful".to_string(),
            data: Some(response),
        }),
        Err(err) => json_response(err.into()),
    }
}

async fn process_authenticate_finish(
    db: Connection<AuthRsDatabase>,
    data: PasskeyAuthenticateFinishRequest,
) -> ApiResult<PasskeyAuthenticateFinishResponse> {
    // Get the authentication state
    let (user_ids, auth_state) = AUTHENTICATIONS.lock().unwrap()
        .remove(&data.authentication_id)
        .ok_or(ApiError::InvalidState("Authentication not found".to_string()))?;
    
    // Initialize Webauthn
    let webauthn = get_webauthn();
    
    // Get credential ID as base64
    let credential_id = general_purpose::STANDARD.encode(&data.credential.id);
    
    // Find user with this credential
    let mut user = User::find_by_credential_id(&db, &credential_id).await
        .map_err(|_| ApiError::NotFound("User not found with this credential".to_string()))?;
    
    // Verify user is allowed
    if !user_ids.is_empty() && !user_ids.contains(&user.id) {
        return Err(ApiError::InvalidState("User not allowed to authenticate with this credential".to_string()));
    }
    
    // Find the passkey
    let _passkey = user.find_passkey_by_credential_id(&credential_id)
        .ok_or(ApiError::NotFound("Passkey not found".to_string()))?;
    
    // Note: We're not using the passkey counter here as authenticate_credential
    // in webauthn-rs 0.3.2 doesn't support custom counter validation
    
    // Verify authentication
    let result = webauthn.authenticate_credential(
        &data.credential,
        &auth_state,
    ).map_err(|e| ApiError::AppError(AppError::WebauthnError(e)))?;
    
    // Update counter if needed
    let mut should_update = false;
    for pk in user.passkeys.iter_mut() {
        if pk.credential_id == credential_id {
            if pk.counter != result.1.counter {
                pk.counter = result.1.counter;
                should_update = true;
            }
            break;
        }
    }
    
    // Update user if counter changed
    if should_update {
        user.update(&db).await
            .map_err(|e| ApiError::AppError(AppError::DatabaseError(e.to_string())))?;
    }
    
    // Generate a fresh token for the user
    let token = User::generate_token();
    user.token = token.clone();
    user.update(&db).await
        .map_err(|e| ApiError::AppError(AppError::DatabaseError(e.to_string())))?;
    
    // Return success with user information and token
    Ok(PasskeyAuthenticateFinishResponse {
        user: user.to_dto(),
        token,
    })
} 