use poem::{handler, web::Json, Result, Response};
use solana_program::system_instruction;
use spl_token::instruction as token_instruction;
use spl_associated_token_account::get_associated_token_address;
use crate::models::{SendSolRequest, SendTokenRequest};
use crate::utils::{
    parse_pubkey, create_error_response, create_success_response, encode_base64
};
use serde::Serialize;

#[derive(Serialize)]
pub struct SendSolResponse {
    pub program_id: String,
    pub accounts: Vec<String>,  // Just array of addresses as strings
    pub instruction_data: String,
}

#[derive(Serialize)]
pub struct SendTokenAccountMeta {
    pub pubkey: String,
    #[serde(rename = "isSigner")]
    pub is_signer: bool,
}

#[derive(Serialize)]
pub struct SendTokenResponse {
    pub program_id: String,
    pub accounts: Vec<SendTokenAccountMeta>,
    pub instruction_data: String,
}

fn validate_send_sol_request(req: &SendSolRequest) -> Result<(), String> {
    if req.from.trim().is_empty() {
        return Err("From address cannot be empty".to_string());
    }
    if req.to.trim().is_empty() {
        return Err("To address cannot be empty".to_string());
    }
    if req.lamports == 0 {
        return Err("Lamports must be greater than 0".to_string());
    }
    Ok(())
}

fn validate_send_token_request(req: &SendTokenRequest) -> Result<(), String> {
    if req.destination.trim().is_empty() {
        return Err("Destination address cannot be empty".to_string());
    }
    if req.mint.trim().is_empty() {
        return Err("Mint address cannot be empty".to_string());
    }
    if req.owner.trim().is_empty() {
        return Err("Owner address cannot be empty".to_string());
    }
    if req.amount == 0 {
        return Err("Amount must be greater than 0".to_string());
    }
    Ok(())
}

#[handler]
pub async fn send_sol(req: Result<Json<SendSolRequest>>) -> Result<Response> {
    // Handle JSON parsing errors
    let Json(req) = match req {
        Ok(json) => json,
        Err(_) => return Ok(create_error_response::<SendSolResponse>("Invalid JSON format in request body")),
    };

    // Validate input
    if let Err(err) = validate_send_sol_request(&req) {
        return Ok(create_error_response::<SendSolResponse>(&err));
    }

    let from = match parse_pubkey(&req.from) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<SendSolResponse>(&format!("Invalid sender address: {}", err))),
    };

    let to = match parse_pubkey(&req.to) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<SendSolResponse>(&format!("Invalid recipient address: {}", err))),
    };

    let instruction = system_instruction::transfer(&from, &to, req.lamports);

    // Format response according to README spec - accounts as array of strings
    let response = SendSolResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction.accounts.iter().map(|acc| acc.pubkey.to_string()).collect(),
        instruction_data: encode_base64(&instruction.data),
    };

    Ok(create_success_response(response))
}

#[handler]
pub async fn send_token(req: Result<Json<SendTokenRequest>>) -> Result<Response> {
    // Handle JSON parsing errors
    let Json(req) = match req {
        Ok(json) => json,
        Err(_) => return Ok(create_error_response::<SendTokenResponse>("Invalid JSON format in request body")),
    };

    // Validate input
    if let Err(err) = validate_send_token_request(&req) {
        return Ok(create_error_response::<SendTokenResponse>(&err));
    }

    let mint = match parse_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<SendTokenResponse>(&format!("Invalid mint address: {}", err))),
    };

    let destination_owner = match parse_pubkey(&req.destination) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<SendTokenResponse>(&format!("Invalid destination owner address: {}", err))),
    };

    let owner = match parse_pubkey(&req.owner) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<SendTokenResponse>(&format!("Invalid token owner address: {}", err))),
    };

    let source = get_associated_token_address(&owner, &mint);
    let destination = get_associated_token_address(&destination_owner, &mint);

    let instruction = match token_instruction::transfer(
        &spl_token::id(),
        &source,
        &destination,
        &owner,
        &[],
        req.amount,
    ) {
        Ok(inst) => inst,
        Err(_) => return Ok(create_error_response::<SendTokenResponse>("Failed to create transfer instruction")),
    };

    // Format response according to README spec - accounts with pubkey and isSigner
    let response = SendTokenResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction.accounts.iter().map(|acc| SendTokenAccountMeta {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        }).collect(),
        instruction_data: encode_base64(&instruction.data),
    };

    Ok(create_success_response(response))
}