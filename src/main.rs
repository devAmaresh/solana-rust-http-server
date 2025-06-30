use poem::{
    listener::TcpListener,
    Route, Server,
    handler, post, get,
    web::Json,
    Result, Response,
};
use ed25519_dalek::{Signer, Verifier, Signature, Keypair, PublicKey};
use solana_program::{
    pubkey::Pubkey,
    system_instruction,
};
use spl_token::instruction as token_instruction;
use serde::{Deserialize, Serialize};
use bs58::{decode, encode};
use base64::{engine::general_purpose, Engine as _};
use std::str::FromStr;
use spl_associated_token_account::get_associated_token_address;

#[derive(Debug, Deserialize)]
struct CreateTokenRequest {
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Debug, Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Debug, Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Debug, Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Debug, Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Debug, Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Serialize)]
struct AccountMetaResponse {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[handler]
async fn generate_keypair() -> Result<Json<ApiResponse<KeypairResponse>>> {
    let mut csprng = rand_07::rngs::OsRng;
    let keypair: Keypair = Keypair::generate(&mut csprng);
    Ok(Json(ApiResponse {
        success: true,
        data: Some(KeypairResponse {
            pubkey: encode(keypair.public.as_bytes()).into_string(),
            secret: encode(&keypair.to_bytes()).into_string(),
        }),
        error: None,
    }))
}

#[handler]
async fn create_token(Json(req): Json<CreateTokenRequest>) -> Result<Json<ApiResponse<InstructionResponse>>> {
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid mint address".to_string()),
        })),
    };
    let mint_authority = match Pubkey::from_str(&req.mint_authority) {
        Ok(pk) => pk,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid mint authority".to_string()),
        })),
    };
    let instruction = match token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        req.decimals,
    ) {
        Ok(inst) => inst,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Failed to create instruction".to_string()),
        })),
    };
    let accounts = instruction.accounts.iter().map(|meta| AccountMetaResponse {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();
    Ok(Json(ApiResponse {
        success: true,
        data: Some(InstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        }),
        error: None,
    }))
}

#[handler]
async fn mint_token(Json(req): Json<MintTokenRequest>) -> Result<Json<ApiResponse<InstructionResponse>>> {
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid mint address".to_string()),
        })),
    };
    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid destination address".to_string()),
        })),
    };
    let authority = match Pubkey::from_str(&req.authority) {
        Ok(pk) => pk,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid authority address".to_string()),
        })),
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
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Failed to create instruction".to_string()),
        })),
    };
    let accounts = instruction.accounts.iter().map(|meta| AccountMetaResponse {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();
    Ok(Json(ApiResponse {
        success: true,
        data: Some(InstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        }),
        error: None,
    }))
}

#[handler]
async fn sign_message(Json(req): Json<SignMessageRequest>) -> Result<Json<ApiResponse<SignMessageResponse>>> {
    let secret_bytes = match decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid base58 secret".to_string()),
        })),
    };
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid secret key".to_string()),
        })),
    };
    let signature = keypair.sign(req.message.as_bytes());
    Ok(Json(ApiResponse {
        success: true,
        data: Some(SignMessageResponse {
            signature: general_purpose::STANDARD.encode(signature.to_bytes()),
            public_key: encode(keypair.public.as_bytes()).into_string(),
            message: req.message,
        }),
        error: None,
    }))
}

#[handler]
async fn verify_message(Json(req): Json<VerifyMessageRequest>) -> Result<Json<ApiResponse<VerifyMessageResponse>>> {
    let pubkey_bytes = match decode(&req.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid base58 public key".to_string()),
        })),
    };
    let public_key = match PublicKey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid public key".to_string()),
        })),
    };
    let signature_bytes = match general_purpose::STANDARD.decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid base64 signature".to_string()),
        })),
    };
    let signature = match Signature::from_bytes(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid signature format".to_string()),
        })),
    };
    let valid = public_key.verify(req.message.as_bytes(), &signature).is_ok();
    Ok(Json(ApiResponse {
        success: true,
        data: Some(VerifyMessageResponse {
            valid,
            message: req.message,
            pubkey: req.pubkey,
        }),
        error: None,
    }))
}

#[handler]
async fn send_sol(Json(req): Json<SendSolRequest>) -> Result<Json<ApiResponse<InstructionResponse>>> {
    let from = match Pubkey::from_str(&req.from) {
        Ok(pk) => pk,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid sender address".to_string()),
        })),
    };
    let to = match Pubkey::from_str(&req.to) {
        Ok(pk) => pk,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid recipient address".to_string()),
        })),
    };
    let instruction = system_instruction::transfer(&from, &to, req.lamports);
    let accounts = instruction.accounts.iter().map(|meta| AccountMetaResponse {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();
    Ok(Json(ApiResponse {
        success: true,
        data: Some(InstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        }),
        error: None,
    }))
}

#[handler]
async fn send_token(Json(req): Json<SendTokenRequest>) -> Result<Json<ApiResponse<InstructionResponse>>> {
    // Parse input addresses
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pk) => pk,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid mint address".to_string()),
        })),
    };
    let destination_owner = match Pubkey::from_str(&req.destination) {
        Ok(pk) => pk,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid destination owner address".to_string()),
        })),
    };
    let owner = match Pubkey::from_str(&req.owner) {
        Ok(pk) => pk,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Invalid token owner address".to_string()),
        })),
    };

    // Derive Associated Token Accounts
    let source = get_associated_token_address(&owner, &mint);
    let destination = get_associated_token_address(&destination_owner, &mint);

    // Create token transfer instruction
    let instruction = match token_instruction::transfer(
        &spl_token::id(),
        &source,
        &destination,
        &owner,  // Owner signs the transfer
        &[],
        req.amount,
    ) {
        Ok(inst) => inst,
        Err(_) => return Ok(Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Failed to create transfer instruction".to_string()),
        })),
    };

    // Prepare response
    let accounts = instruction.accounts.iter().map(|meta| AccountMetaResponse {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();

    Ok(Json(ApiResponse {
        success: true,
        data: Some(InstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        }),
        error: None,
    }))
}

#[handler]
async fn not_found() -> Response {
    Response::builder()
        .status(poem::http::StatusCode::NOT_FOUND)
        .body("Endpoint not found")
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = Route::new()
        .at("/keypair", post(generate_keypair))
        .at("/token/create", post(create_token))
        .at("/token/mint", post(mint_token))
        .at("/message/sign", post(sign_message))
        .at("/message/verify", post(verify_message))
        .at("/send/sol", post(send_sol))
        .at("/send/token", post(send_token))
        .at("/*", get(not_found).post(not_found));

    println!("Server running at http://127.0.0.1:8080");
    Server::new(TcpListener::bind("127.0.0.1:8080"))
        .run(app)
        .await
}
