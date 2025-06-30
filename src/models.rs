use serde::{Deserialize, Serialize};

// Request Models
#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    pub mint_authority: String,  // Follow Rust conventions with serde rename
    pub mint: String,
    pub decimals: u8,
}

#[derive(Debug, Deserialize)]
pub struct MintTokenRequest {
    pub mint: String,
    pub destination: String,
    pub authority: String,
    pub amount: u64,
}

#[derive(Debug, Deserialize)]
pub struct SignMessageRequest {
    pub message: String,
    pub secret: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyMessageRequest {
    pub message: String,
    pub signature: String,
    pub pubkey: String,
}

#[derive(Debug, Deserialize)]
pub struct SendSolRequest {
    pub from: String,
    pub to: String,
    pub lamports: u64,
}

#[derive(Debug, Deserialize)]
pub struct SendTokenRequest {
    pub destination: String,
    pub mint: String,
    pub owner: String,
    pub amount: u64,
}

// Response Models
#[derive(Serialize)]
pub struct KeypairResponse {
    pub pubkey: String,
    pub secret: String,
}

#[derive(Serialize)]
pub struct AccountMetaResponse {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Serialize)]
pub struct InstructionResponse {
    pub program_id: String,
    pub accounts: Vec<AccountMetaResponse>,
    pub instruction_data: String,
}

#[derive(Serialize)]
pub struct SignMessageResponse {
    pub signature: String,
    pub public_key: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct VerifyMessageResponse {
    pub valid: bool,
    pub message: String,
    pub pubkey: String,
}

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}