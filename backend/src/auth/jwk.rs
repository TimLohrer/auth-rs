use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rocket::serde::{Serialize};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::fs;

use crate::auth::jwt::{DEFAULT_PRIV_KEY, DEFAULT_PUB_KEY};

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub kid: String,
    pub alg: String,
    pub n: String,
    pub e: String,
    pub value: String,
}

pub fn load_private_key() -> anyhow::Result<RsaPrivateKey> {
    let pem = fs::read_to_string(DEFAULT_PRIV_KEY)?;
    let key = RsaPrivateKey::from_pkcs1_pem(&pem)?;
    Ok(key)
}

pub fn jwk_from_pubkey(pubkey: &RsaPublicKey, kid: &str) -> Jwk {
    let n = URL_SAFE_NO_PAD.encode(pubkey.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(pubkey.e().to_bytes_be());
    Jwk {
        kty: "RSA".into(),
        use_: "sig".into(),
        kid: kid.into(),
        alg: "RS256".into(),
        n,
        e,
        value: pubkey.to_pkcs1_pem(LineEnding::LF).unwrap_or_default()
    }
}

pub fn load_public_key() -> anyhow::Result<RsaPublicKey> {
    let pem = fs::read_to_string(DEFAULT_PUB_KEY)?;
    let key = RsaPublicKey::from_pkcs1_pem(&pem)?;
    Ok(key)
}
