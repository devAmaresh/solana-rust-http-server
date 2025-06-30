use poem::{handler, web::Json, Result, Response};
use solana_program::system_instruction;
use spl_token::instruction as token_instruction;
use spl_associated_token_account::get_associated_token_address;
use crate::models::{SendSolRequest, SendTokenRequest, InstructionResponse};
use crate::utils::{
    parse_pubkey, create_error_response, create_success_response,
    convert_account_metas, encode_base64
};

#[handler]
pub async fn send_sol(req: Result<Json<SendSolRequest>>) -> Result<Response> {
    // Handle JSON parsing errors
    let Json(req) = match req {
        Ok(json) => json,
        Err(_) => return Ok(create_error_response::<InstructionResponse>("Invalid JSON format in request body")),
    };

    let from = match parse_pubkey(&req.from) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<InstructionResponse>(&format!("Invalid sender address: {}", err))),
    };

    let to = match parse_pubkey(&req.to) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<InstructionResponse>(&format!("Invalid recipient address: {}", err))),
    };

    let instruction = system_instruction::transfer(&from, &to, req.lamports);

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: convert_account_metas(&instruction.accounts),
        instruction_data: encode_base64(&instruction.data),
    };

    Ok(create_success_response(response))
}

#[handler]
pub async fn send_token(req: Result<Json<SendTokenRequest>>) -> Result<Response> {
    // Handle JSON parsing errors
    let Json(req) = match req {
        Ok(json) => json,
        Err(_) => return Ok(create_error_response::<InstructionResponse>("Invalid JSON format in request body")),
    };

    let mint = match parse_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<InstructionResponse>(&format!("Invalid mint address: {}", err))),
    };

    let destination_owner = match parse_pubkey(&req.destination) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<InstructionResponse>(&format!("Invalid destination owner address: {}", err))),
    };

    let owner = match parse_pubkey(&req.owner) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<InstructionResponse>(&format!("Invalid token owner address: {}", err))),
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
        Err(_) => return Ok(create_error_response::<InstructionResponse>("Failed to create transfer instruction")),
    };

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: convert_account_metas(&instruction.accounts),
        instruction_data: encode_base64(&instruction.data),
    };

    Ok(create_success_response(response))
}