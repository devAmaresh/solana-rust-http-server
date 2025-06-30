mod handlers;
mod models;
mod utils;

use poem::{
    listener::TcpListener,
    Route, Server, EndpointExt,
    post, get,
    middleware::Cors,
};
use handlers::*;
use std::env;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let host = "0.0.0.0"; 
    let addr = format!("{}:{}", host, port);

    let app = Route::new()
        .at("/keypair", post(generate_keypair))
        .at("/token/create", post(create_token))
        .at("/token/mint", post(mint_token))
        .at("/message/sign", post(sign_message))
        .at("/message/verify", post(verify_message))
        .at("/send/sol", post(send_sol))
        .at("/send/token", post(send_token))
        .at("/*", get(not_found).post(not_found))
        .with(Cors::new()
            .allow_origins_fn(|_| true) 
            .allow_methods(vec!["GET", "POST", "OPTIONS"])
            .allow_headers(vec!["content-type", "authorization"])
        );

    println!("Server running at http://{}", addr);
    Server::new(TcpListener::bind(&addr))
        .run(app)
        .await
}
