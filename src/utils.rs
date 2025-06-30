use ed25519_dalek::{Keypair, PublicKey, Signature};
use bs58::{decode, encode};
use base64::{engine::general_purpose, Engine as _};
use solana_program::pubkey::Pubkey;
use std::str::FromStr;
use poem::Response;
use crate::models::{AccountMetaResponse, ApiResponse};

pub fn generate_new_keypair() -> Keypair {
    let mut csprng = rand_07::rngs::OsRng;
    Keypair::generate(&mut csprng)
}

pub fn decode_base58(input: &str) -> Result<Vec<u8>, String> {
    decode(input).into_vec().map_err(|_| "Invalid base58 encoding".to_string())
}

pub fn encode_base58(input: &[u8]) -> String {
    encode(input).into_string()
}

pub fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD.decode(input).map_err(|_| "Invalid base64 encoding".to_string())
}

pub fn encode_base64(input: &[u8]) -> String {
    general_purpose::STANDARD.encode(input)
}

pub fn parse_pubkey(pubkey_str: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(pubkey_str).map_err(|_| "Invalid public key".to_string())
}

pub fn parse_keypair(secret_bytes: &[u8]) -> Result<Keypair, String> {
    Keypair::from_bytes(secret_bytes).map_err(|_| "Invalid secret key".to_string())
}

pub fn parse_public_key(pubkey_bytes: &[u8]) -> Result<PublicKey, String> {
    PublicKey::from_bytes(pubkey_bytes).map_err(|_| "Invalid public key bytes".to_string())
}

pub fn parse_signature(signature_bytes: &[u8]) -> Result<Signature, String> {
    Signature::from_bytes(signature_bytes).map_err(|_| "Invalid signature format".to_string())
}

// Return JSON with 400 status for errors
pub fn create_error_response<T: serde::Serialize>(error_msg: &str) -> Response {
    let error_response = ApiResponse::<T> {
        success: false,
        data: None,
        error: Some(error_msg.to_string()),
    };
    
    Response::builder()
        .status(poem::http::StatusCode::BAD_REQUEST)
        .content_type("application/json")
        .body(serde_json::to_string(&error_response).unwrap())
}

// Return JSON with 200 status for success
pub fn create_success_response<T: serde::Serialize>(data: T) -> Response {
    let success_response = ApiResponse {
        success: true,
        data: Some(data),
        error: None,
    };
    
    Response::builder()
        .status(poem::http::StatusCode::OK)
        .content_type("application/json")
        .body(serde_json::to_string(&success_response).unwrap())
}

pub fn convert_account_metas(accounts: &[solana_program::instruction::AccountMeta]) -> Vec<AccountMetaResponse> {
    accounts.iter().map(|meta| AccountMetaResponse {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect()
}