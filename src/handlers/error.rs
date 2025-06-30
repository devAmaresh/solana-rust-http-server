use poem::{handler, Response};

#[handler]
pub async fn not_found() -> Response {
    Response::builder()
        .status(poem::http::StatusCode::NOT_FOUND)
        .body("Endpoint not found")
}