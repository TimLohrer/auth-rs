use jsonwebtoken::{EncodingKey, DecodingKey, Header, Validation, encode, decode, TokenData};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rocket::serde::{Serialize, Deserialize};
use serde_json::Value;
use std::fs;
use std::path::Path;
use anyhow::Context;

pub const DEFAULT_KEY_DIR: &str = "data/keys";
pub const DEFAULT_PRIV_KEY: &str = "data/keys/oidc_private.pem";
pub const DEFAULT_PUB_KEY: &str = "data/keys/oidc_public.pem";

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct Claims {
    pub sub: String,
    pub aud: String,
    pub iss: String,
    pub exp: usize,
    pub iat: usize,
    pub data: Option<Value>,
}

pub fn ensure_keys_exist() -> anyhow::Result<()> {
    if !Path::new(DEFAULT_KEY_DIR).exists() {
        fs::create_dir_all(DEFAULT_KEY_DIR)?;
    }

    if !Path::new(DEFAULT_PRIV_KEY).exists() || !Path::new(DEFAULT_PUB_KEY).exists() {
        // generate 2048-bit RSA keypair
        let private = RsaPrivateKey::new(&mut OsRng, 2048)
            .context("Failed to generate RSA private key")?;
        let public = RsaPublicKey::from(&private);

        // write private key PEM
        let priv_pem = private.to_pkcs1_pem(Default::default())?;
        fs::write(DEFAULT_PRIV_KEY, priv_pem.as_bytes())?;

        // write public key PEM
        let pub_pem = public.to_pkcs1_pem(Default::default())?;
        fs::write(DEFAULT_PUB_KEY, pub_pem.as_bytes())?;
    }

    Ok(())
}

pub fn load_private_key_pem() -> anyhow::Result<String> {
    ensure_keys_exist()?;
    let pem = fs::read_to_string(DEFAULT_PRIV_KEY)?;
    Ok(pem)
}

pub fn load_public_key_pem() -> anyhow::Result<String> {
    ensure_keys_exist()?;
    let pem = fs::read_to_string(DEFAULT_PUB_KEY)?;
    Ok(pem)
}

pub fn sign_id_token(claims: &Claims) -> anyhow::Result<String> {
    let private_pem = load_private_key_pem()?;
    let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())?;
    let header = Header::new(jsonwebtoken::Algorithm::RS256);
    let token = encode(&header, claims, &encoding_key)?;
    Ok(token)
}

pub fn verify_id_token(token: &str) -> anyhow::Result<TokenData<Claims>> {
    let public_pem = load_public_key_pem()?;
    let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())?;
    let validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    let data = decode::<Claims>(token, &decoding_key, &validation)?;
    Ok(data)
}
