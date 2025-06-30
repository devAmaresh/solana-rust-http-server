use poem::{handler, web::Json, Result};
use serde_json::json;

#[handler]
pub async fn health_check() -> Result<Json<serde_json::Value>> {
    Ok(Json(json!({
        "status": "healthy",
        "service": "solana-fellowship-server",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}