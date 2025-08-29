use crate::{BoxBody, full, json};
use crate::{Response, StatusCode};

pub fn internal_server_error() -> Response<BoxBody> {
    return Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header("content-type", "application/json")
        .body(full(
            json!({
                "error": "Failed to read request body",
                "status": 500
            })
            .to_string(),
        ))
        .unwrap();
}

pub fn ok() -> Response<BoxBody> {
    return Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(full(
            json!({
                "message": "uploaded successful",
                "status": 200
            })
            .to_string(),
        ))
        .unwrap();
}
