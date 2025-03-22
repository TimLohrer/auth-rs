use std::{collections::HashMap, time::Duration};

use anyhow::Result;
use mongodb::bson::{doc, Uuid};
use rocket::tokio::{spawn, time::sleep};
use rocket_db_pools::Connection;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::{
    db::{get_main_db, AuthRsDatabase},
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        user::User,
    },
    MFA_SESSIONS,
};

use super::auth::AuthEntity;

#[derive(Debug, Clone)]
pub enum MfaState {
    Pending,
    Complete,
}

#[derive(Debug, Clone)]
pub enum MfaType {
    TOTP,
    EnableTOTP,
}

#[derive(Debug, Clone)]
pub struct MfaHandler {
    pub flow_id: Uuid,
    pub state: MfaState,
    pub r#type: MfaType,
    pub user: User,
    pub totp: Option<TOTP>,
}

impl MfaHandler {
    pub fn is_mfa_required(user: &User) -> bool {
        user.totp_secret.is_some()
    }

    pub async fn start_enable_flow(user: &User) -> Result<Self, String> {
        let flow = Self {
            flow_id: Uuid::new(),
            state: MfaState::Pending,
            r#type: MfaType::EnableTOTP,
            user: user.clone(),
            totp: Some(
                TOTP::new(
                    Algorithm::SHA1,
                    6,
                    1,
                    30,
                    Secret::generate_secret().to_bytes().unwrap(),
                    Some("auth-rs".to_string()), /* CHANGE ME */
                    user.email.to_string(),
                )
                .unwrap(),
            ),
        };

        let mut mfa_sessions = MFA_SESSIONS.lock().await;
        mfa_sessions.insert(flow.flow_id, flow.clone());
        drop(mfa_sessions);

        //TODO: Store this state in the db with a timestamp, and check for expiration
        //  We can not and should not rely on the application not crashing or restarting
        //  This application should be completely stateless
        // invalidate flow after 5 minutes
        spawn(async move {
            sleep(Duration::from_secs(300)).await;

            let mut mfa_sessions = MFA_SESSIONS.lock().await;
            mfa_sessions.remove(&flow.flow_id);
            drop(mfa_sessions);
        });

        Ok(flow)
    }

    pub async fn start_login_flow(user: &User) -> Result<Self, String> {
        if user.totp_secret.is_none() {
            return Err("User does not have TOTP enabled".to_string());
        }

        let mut flow = Self {
            flow_id: Uuid::new(),
            state: MfaState::Pending,
            r#type: MfaType::TOTP,
            user: user.clone(),
            totp: None,
        };

        flow.totp = Some(
            TOTP::new(
                Algorithm::SHA1,
                6,
                1,
                30,
                Secret::Encoded(user.totp_secret.as_ref().unwrap().to_string())
                    .to_bytes()
                    .unwrap(),
                Some("auth-rs".to_string()), /* CHANGE ME */
                user.email.to_string(),
            )
            .unwrap(),
        );

        let mut mfa_sessions = MFA_SESSIONS.lock().await;
        mfa_sessions.insert(flow.flow_id, flow.clone());
        drop(mfa_sessions);

        //TODO: Store this state in the db with a timestamp, and check for expiration
        //  We can not and should not rely on the application not crashing or restarting
        //  This application should be completely stateless
        // invalidate flow after 5 minutes
        spawn(async move {
            sleep(Duration::from_secs(300)).await;

            let mut mfa_sessions = MFA_SESSIONS.lock().await;
            mfa_sessions.remove(&flow.flow_id);
            drop(mfa_sessions);
        });

        Ok(flow)
    }

    pub async fn verify_current_totp(&self, code: &str) -> bool {
        if self.totp.is_none() || code.is_empty() {
            return false;
        }

        if self.totp.as_ref().unwrap().generate_current().unwrap() == code {
            let mut mfa_sessions = MFA_SESSIONS.lock().await;
            mfa_sessions.remove(&self.flow_id);
            drop(mfa_sessions);

            true
        } else {
            false
        }
    }

    pub async fn verify_totp(user: &User, secret: String, code: &str) -> bool {
        let totp_result = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(secret).to_bytes().unwrap(),
            Some("auth-rs".to_string()), /* CHANGE ME */
            user.email.to_string(),
        );

        if totp_result.is_err() {
            return false;
        }

        totp_result.unwrap().check_current(code).unwrap_or(false)
    }

    pub async fn disable_totp(
        user: &mut User,
        req_user: AuthEntity,
        db: &Connection<AuthRsDatabase>,
    ) -> Result<User, String> {
        let mut new_values = HashMap::from([("totpSecret".to_string(), "".to_string())]);
        let mut old_values = HashMap::from([(
            "totpSecret".to_string(),
            user.totp_secret
                .as_ref()
                .unwrap_or(&"".to_string())
                .to_string(),
        )]);

        user.totp_secret = None;

        let new_token = User::generate_token();
        new_values.insert("token".to_string(), new_token.clone());
        old_values.insert("token".to_string(), user.token.to_string());

        user.token = new_token;

        let filter = doc! {
            "_id": user.id
        };
        match get_main_db(db)
            .collection(User::COLLECTION_NAME)
            .replace_one(filter, user.clone(), None)
            .await
        {
            Ok(_) => {
                match AuditLog::new(
                    user.id,
                    AuditLogEntityType::User,
                    AuditLogAction::Update,
                    "Disable TOTP.".to_string(),
                    req_user.user_id,
                    Some(old_values),
                    Some(new_values),
                )
                .insert(db)
                .await
                {
                    Ok(_) => (),
                    Err(err) => eprintln!("{:?}", err),
                };
                Ok(user.to_owned())
            }
            Err(err) => Err(format!("Failed to disable TOTP: {:?}", err)),
        }
    }
}

impl PartialEq for MfaState {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (MfaState::Pending, MfaState::Pending) | (MfaState::Complete, MfaState::Complete)
        )
    }
}

impl PartialEq for MfaType {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (MfaType::TOTP, MfaType::TOTP) | (MfaType::EnableTOTP, MfaType::EnableTOTP)
        )
    }
}
