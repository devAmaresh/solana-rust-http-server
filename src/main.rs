mod handlers;
mod models;
mod utils;

use poem::{
    listener::TcpListener,
    Route, Server,
    post, get,
};
use handlers::*;

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
