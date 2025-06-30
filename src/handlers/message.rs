use poem::{handler, web::Json, Result, Response};
use ed25519_dalek::{Signer, Verifier};
use crate::models::{SignMessageRequest, VerifyMessageRequest, SignMessageResponse, VerifyMessageResponse};
use crate::utils::{
    decode_base58, encode_base58, decode_base64, encode_base64,
    parse_keypair, parse_public_key, parse_signature,
    create_error_response, create_success_response
};

fn validate_sign_request(req: &SignMessageRequest) -> Result<(), String> {
    if req.message.trim().is_empty() {
        return Err("Message cannot be empty".to_string());
    }
    if req.secret.trim().is_empty() {
        return Err("Secret key cannot be empty".to_string());
    }
    Ok(())
}

fn validate_verify_request(req: &VerifyMessageRequest) -> Result<(), String> {
    if req.message.trim().is_empty() {
        return Err("Message cannot be empty".to_string());
    }
    if req.signature.trim().is_empty() {
        return Err("Signature cannot be empty".to_string());
    }
    if req.pubkey.trim().is_empty() {
        return Err("Public key cannot be empty".to_string());
    }
    Ok(())
}

#[handler]
pub async fn sign_message(req: Result<Json<SignMessageRequest>>) -> Result<Response> {
    // Handle JSON parsing errors
    let Json(req) = match req {
        Ok(json) => json,
        Err(_) => return Ok(create_error_response::<SignMessageResponse>("Invalid JSON format in request body")),
    };

    // Validate input
    if let Err(err) = validate_sign_request(&req) {
        return Ok(create_error_response::<SignMessageResponse>(&err));
    }

    let secret_bytes = match decode_base58(&req.secret) {
        Ok(bytes) => bytes,
        Err(err) => return Ok(create_error_response::<SignMessageResponse>(&format!("Invalid base58 secret: {}", err))),
    };

    let keypair = match parse_keypair(&secret_bytes) {
        Ok(kp) => kp,
        Err(err) => return Ok(create_error_response::<SignMessageResponse>(&format!("Invalid secret key: {}", err))),
    };

    let signature = keypair.sign(req.message.as_bytes());

    let response = SignMessageResponse {
        signature: encode_base64(&signature.to_bytes()),
        public_key: encode_base58(keypair.public.as_bytes()),
        message: req.message,
    };

    Ok(create_success_response(response))
}

#[handler]
pub async fn verify_message(req: Result<Json<VerifyMessageRequest>>) -> Result<Response> {
    // Handle JSON parsing errors
    let Json(req) = match req {
        Ok(json) => json,
        Err(_) => return Ok(create_error_response::<VerifyMessageResponse>("Invalid JSON format in request body")),
    };

    // Validate input
    if let Err(err) = validate_verify_request(&req) {
        return Ok(create_error_response::<VerifyMessageResponse>(&err));
    }

    let pubkey_bytes = match decode_base58(&req.pubkey) {
        Ok(bytes) => bytes,
        Err(err) => return Ok(create_error_response::<VerifyMessageResponse>(&format!("Invalid base58 public key: {}", err))),
    };

    let public_key = match parse_public_key(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<VerifyMessageResponse>(&format!("Invalid public key: {}", err))),
    };

    let signature_bytes = match decode_base64(&req.signature) {
        Ok(bytes) => bytes,
        Err(err) => return Ok(create_error_response::<VerifyMessageResponse>(&format!("Invalid base64 signature: {}", err))),
    };

    let signature = match parse_signature(&signature_bytes) {
        Ok(sig) => sig,
        Err(err) => return Ok(create_error_response::<VerifyMessageResponse>(&format!("Invalid signature format: {}", err))),
    };

    let valid = public_key.verify(req.message.as_bytes(), &signature).is_ok();

    let response = VerifyMessageResponse {
        valid,
        message: req.message,
        pubkey: req.pubkey,
    };

    Ok(create_success_response(response))
}