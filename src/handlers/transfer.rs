use poem::{handler, web::Json, Result};
use solana_program::system_instruction;
use spl_token::instruction as token_instruction;
use spl_associated_token_account::get_associated_token_address;
use crate::models::{SendSolRequest, SendTokenRequest, InstructionResponse, ApiResponse};
use crate::utils::{
    parse_pubkey, create_error_response, create_success_response,
    convert_account_metas, encode_base64
};

#[handler]
pub async fn send_sol(Json(req): Json<SendSolRequest>) -> Result<Json<ApiResponse<InstructionResponse>>> {
    let from = match parse_pubkey(&req.from) {
        Ok(pk) => pk,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid sender address: {}", err)))),
    };

    let to = match parse_pubkey(&req.to) {
        Ok(pk) => pk,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid recipient address: {}", err)))),
    };

    let instruction = system_instruction::transfer(&from, &to, req.lamports);

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: convert_account_metas(&instruction.accounts),
        instruction_data: encode_base64(&instruction.data),
    };

    Ok(Json(create_success_response(response)))
}

#[handler]
pub async fn send_token(Json(req): Json<SendTokenRequest>) -> Result<Json<ApiResponse<InstructionResponse>>> {
    let mint = match parse_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid mint address: {}", err)))),
    };

    let destination_owner = match parse_pubkey(&req.destination) {
        Ok(pk) => pk,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid destination owner address: {}", err)))),
    };

    let owner = match parse_pubkey(&req.owner) {
        Ok(pk) => pk,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid token owner address: {}", err)))),
    };

    // Derive Associated Token Accounts
    let source = get_associated_token_address(&owner, &mint);
    let destination = get_associated_token_address(&destination_owner, &mint);

    // Create token transfer instruction
    let instruction = match token_instruction::transfer(
        &spl_token::id(),
        &source,
        &destination,
        &owner,
        &[],
        req.amount,
    ) {
        Ok(inst) => inst,
        Err(_) => return Ok(Json(create_error_response("Failed to create transfer instruction"))),
    };

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: convert_account_metas(&instruction.accounts),
        instruction_data: encode_base64(&instruction.data),
    };

    Ok(Json(create_success_response(response)))
}