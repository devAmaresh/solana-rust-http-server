use poem::{handler, web::Json, Result, Response};
use spl_token::instruction as token_instruction;
use crate::models::{CreateTokenRequest, MintTokenRequest, InstructionResponse};
use crate::utils::{parse_pubkey, create_error_response, create_success_response, convert_account_metas, encode_base64};

fn validate_create_token_request(req: &CreateTokenRequest) -> Result<(), String> {
    if req.mint_authority.trim().is_empty() {
        return Err("Mint authority cannot be empty".to_string());
    }
    if req.mint.trim().is_empty() {
        return Err("Mint address cannot be empty".to_string());
    }
    if req.decimals > 9 {
        return Err("Decimals cannot exceed 9".to_string());
    }
    Ok(())
}

fn validate_mint_token_request(req: &MintTokenRequest) -> Result<(), String> {
    if req.mint.trim().is_empty() {
        return Err("Mint address cannot be empty".to_string());
    }
    if req.destination.trim().is_empty() {
        return Err("Destination address cannot be empty".to_string());
    }
    if req.authority.trim().is_empty() {
        return Err("Authority address cannot be empty".to_string());
    }
    if req.amount == 0 {
        return Err("Amount must be greater than 0".to_string());
    }
    Ok(())
}

#[handler]
pub async fn create_token(req: Result<Json<CreateTokenRequest>>) -> Result<Response> {
    // Handle JSON parsing errors
    let Json(req) = match req {
        Ok(json) => json,
        Err(_) => return Ok(create_error_response::<InstructionResponse>("Invalid JSON format in request body")),
    };

    // Validate input
    if let Err(err) = validate_create_token_request(&req) {
        return Ok(create_error_response::<InstructionResponse>(&err));
    }

    let mint = match parse_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<InstructionResponse>(&format!("Invalid mint address: {}", err))),
    };

    let mint_authority = match parse_pubkey(&req.mint_authority) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<InstructionResponse>(&format!("Invalid mint authority: {}", err))),
    };

    let instruction = match token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        req.decimals,
    ) {
        Ok(inst) => inst,
        Err(_) => return Ok(create_error_response::<InstructionResponse>("Failed to create instruction")),
    };

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: convert_account_metas(&instruction.accounts),
        instruction_data: encode_base64(&instruction.data),
    };

    Ok(create_success_response(response))
}

#[handler]
pub async fn mint_token(req: Result<Json<MintTokenRequest>>) -> Result<Response> {
    // Handle JSON parsing errors
    let Json(req) = match req {
        Ok(json) => json,
        Err(_) => return Ok(create_error_response::<InstructionResponse>("Invalid JSON format in request body")),
    };

    // Validate input
    if let Err(err) = validate_mint_token_request(&req) {
        return Ok(create_error_response::<InstructionResponse>(&err));
    }

    let mint = match parse_pubkey(&req.mint) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<InstructionResponse>(&format!("Invalid mint address: {}", err))),
    };

    let destination = match parse_pubkey(&req.destination) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<InstructionResponse>(&format!("Invalid destination address: {}", err))),
    };

    let authority = match parse_pubkey(&req.authority) {
        Ok(pk) => pk,
        Err(err) => return Ok(create_error_response::<InstructionResponse>(&format!("Invalid authority address: {}", err))),
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
        Err(_) => return Ok(create_error_response::<InstructionResponse>("Failed to create instruction")),
    };

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: convert_account_metas(&instruction.accounts),
        instruction_data: encode_base64(&instruction.data),
    };

    Ok(create_success_response(response))
}