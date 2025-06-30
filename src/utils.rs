use ed25519_dalek::{Keypair, PublicKey, Signature};
use bs58::{decode, encode};
use base64::{engine::general_purpose, Engine as _};
use solana_program::pubkey::Pubkey;
use std::str::FromStr;
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

pub fn create_error_response<T>(error_msg: &str) -> ApiResponse<T> {
    ApiResponse {
        success: false,
        data: None,
        error: Some(error_msg.to_string()),
    }
}

pub fn create_success_response<T>(data: T) -> ApiResponse<T> {
    ApiResponse {
        success: true,
        data: Some(data),
        error: None,
    }
}

pub fn convert_account_metas(accounts: &[solana_program::instruction::AccountMeta]) -> Vec<AccountMetaResponse> {
    accounts.iter().map(|meta| AccountMetaResponse {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect()
}