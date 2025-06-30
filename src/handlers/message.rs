use poem::{handler, web::Json, Result};
use ed25519_dalek::{Signer, Verifier};
use crate::models::{SignMessageRequest, VerifyMessageRequest, SignMessageResponse, VerifyMessageResponse, ApiResponse};
use crate::utils::{
    decode_base58, encode_base58, decode_base64, encode_base64,
    parse_keypair, parse_public_key, parse_signature,
    create_error_response, create_success_response
};

#[handler]
pub async fn sign_message(Json(req): Json<SignMessageRequest>) -> Result<Json<ApiResponse<SignMessageResponse>>> {
    let secret_bytes = match decode_base58(&req.secret) {
        Ok(bytes) => bytes,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid base58 secret: {}", err)))),
    };

    let keypair = match parse_keypair(&secret_bytes) {
        Ok(kp) => kp,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid secret key: {}", err)))),
    };

    let signature = keypair.sign(req.message.as_bytes());

    let response = SignMessageResponse {
        signature: encode_base64(&signature.to_bytes()),
        public_key: encode_base58(keypair.public.as_bytes()),
        message: req.message,
    };

    Ok(Json(create_success_response(response)))
}

#[handler]
pub async fn verify_message(Json(req): Json<VerifyMessageRequest>) -> Result<Json<ApiResponse<VerifyMessageResponse>>> {
    let pubkey_bytes = match decode_base58(&req.pubkey) {
        Ok(bytes) => bytes,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid base58 public key: {}", err)))),
    };

    let public_key = match parse_public_key(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid public key: {}", err)))),
    };

    let signature_bytes = match decode_base64(&req.signature) {
        Ok(bytes) => bytes,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid base64 signature: {}", err)))),
    };

    let signature = match parse_signature(&signature_bytes) {
        Ok(sig) => sig,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid signature format: {}", err)))),
    };

    let valid = public_key.verify(req.message.as_bytes(), &signature).is_ok();

    let response = VerifyMessageResponse {
        valid,
        message: req.message,
        pubkey: req.pubkey,
    };

    Ok(Json(create_success_response(response)))
}