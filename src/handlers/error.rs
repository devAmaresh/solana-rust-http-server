use poem::{handler, Response};

#[handler]
pub async fn not_found() -> Response {
    Response::builder()
        .status(poem::http::StatusCode::BAD_REQUEST)
        .content_type("application/json")
        .body(r#"{"success": false, "error": "Endpoint not found"}"#)
}