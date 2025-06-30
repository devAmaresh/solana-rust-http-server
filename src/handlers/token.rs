use poem::{handler, web::Json, Result};
use spl_token::instruction as token_instruction;
use crate::models::{CreateTokenRequest, MintTokenRequest, InstructionResponse, ApiResponse};
use crate::utils::{parse_pubkey, create_error_response, create_success_response, convert_account_metas, encode_base64};

#[handler]
pub async fn create_token(Json(req): Json<CreateTokenRequest>) -> Result<Json<ApiResponse<InstructionResponse>>> {
    let mint = match parse_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid mint address: {}", err)))),
    };

    let mint_authority = match parse_pubkey(&req.mint_authority) {
        Ok(pk) => pk,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid mint authority: {}", err)))),
    };

    let instruction = match token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        req.decimals,
    ) {
        Ok(inst) => inst,
        Err(_) => return Ok(Json(create_error_response("Failed to create instruction"))),
    };

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: convert_account_metas(&instruction.accounts),
        instruction_data: encode_base64(&instruction.data),
    };

    Ok(Json(create_success_response(response)))
}

#[handler]
pub async fn mint_token(Json(req): Json<MintTokenRequest>) -> Result<Json<ApiResponse<InstructionResponse>>> {
    let mint = match parse_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid mint address: {}", err)))),
    };

    let destination = match parse_pubkey(&req.destination) {
        Ok(pk) => pk,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid destination address: {}", err)))),
    };

    let authority = match parse_pubkey(&req.authority) {
        Ok(pk) => pk,
        Err(err) => return Ok(Json(create_error_response(&format!("Invalid authority address: {}", err)))),
    };

    let instruction = match token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        req.amount,
    ) {
        Ok(inst) => inst,
        Err(_) => return Ok(Json(create_error_response("Failed to create instruction"))),
    };

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: convert_account_metas(&instruction.accounts),
        instruction_data: encode_base64(&instruction.data),
    };

    Ok(Json(create_success_response(response)))
}