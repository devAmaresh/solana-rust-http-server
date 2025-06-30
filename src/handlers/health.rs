use poem::{handler, Result, Response};
use serde_json::json;

#[handler]
pub async fn health_check() -> Result<Response> {
    let health_data = json!({
        "status": "healthy",
        "service": "solana-fellowship-server",
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    Ok(Response::builder()
        .status(poem::http::StatusCode::OK)
        .content_type("application/json")
        .body(serde_json::to_string(&json!({
            "success": true,
            "data": health_data
        })).unwrap()))
}