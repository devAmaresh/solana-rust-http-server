use poem::{handler, Result, Response};
use crate::models::KeypairResponse;
use crate::utils::{generate_new_keypair, encode_base58, create_success_response};

#[handler]
pub async fn generate_keypair() -> Result<Response> {
    let keypair = generate_new_keypair();
    
    let response = KeypairResponse {
        pubkey: encode_base58(keypair.public.as_bytes()),
        secret: encode_base58(&keypair.to_bytes()),
    };

    Ok(create_success_response(response))
}