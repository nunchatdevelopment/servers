mod utils;
use utils::responses;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;
type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;
use http_body_util::BodyExt;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, body::Incoming as IncomingBody};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde_json::json;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::fs;
use tokio::net::TcpListener;

fn full<T: Into<bytes::Bytes>>(chunk: T) -> BoxBody {
    http_body_util::Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

fn extract_boundary(media_type: &str) -> Option<String> {
    media_type.split(';').find_map(|part| {
        let trimmed = part.trim();
        if trimmed.starts_with("boundary=") {
            Some(trimmed[9..].trim_matches('"').to_string())
        } else {
            None
        }
    })
}

struct FormData {
    file_data: Option<Vec<u8>>,
    handle_as: Option<String>,
}

fn find_parts(body: &[u8], boundary: &str) -> Vec<(usize, usize)> {
    let mut parts = Vec::new();
    let boundary_marker = format!("--{}", boundary).into_bytes();
    let final_boundary = format!("--{}--", boundary).into_bytes();
    
    let mut start = 0;
    while start < body.len() {
        if let Some(pos) = body[start..].windows(boundary_marker.len())
            .position(|window| window == &boundary_marker[..]) {
            
            let boundary_start = start + pos;
            let content_start = boundary_start + boundary_marker.len();
            
            let mut actual_start = content_start;
            if actual_start < body.len() && body[actual_start] == b'\r' {
                actual_start += 1;
            }
            if actual_start < body.len() && body[actual_start] == b'\n' {
                actual_start += 1;
            }
            
            let next_boundary = body[actual_start..].windows(boundary_marker.len())
                .position(|window| window == &boundary_marker[..])
                .map(|p| actual_start + p);
            
            let final_boundary_pos = body[actual_start..].windows(final_boundary.len())
                .position(|window| window == &final_boundary[..])
                .map(|p| actual_start + p);
            
            let end = next_boundary
                .or(final_boundary_pos)
                .unwrap_or(body.len());
            
            if actual_start < end {
                parts.push((actual_start, end));
            }
            
            start = end;
        } else {
            break;
        }
    }
    
    parts
}

fn parse_multipart_form(body: &[u8], boundary: &str) -> FormData {
    let mut form_data = FormData {
        file_data: None,
        handle_as: None,
    };

    let parts = find_parts(body, boundary);
    
    for (start, end) in parts {
        let part = &body[start..end];
        
        if let Some(header_end_pos) = part.windows(4)
            .position(|window| window == b"\r\n\r\n") {
            
            let headers = &part[..header_end_pos];
            let headers_str = String::from_utf8_lossy(headers);
            let content_start = header_end_pos + 4;
            
            if headers_str.contains("filename=") {
                let mut content_end = part.len();
                
                if content_end >= 2 && &part[content_end-2..content_end] == b"\r\n" {
                    content_end -= 2;
                } else if content_end >= 1 && part[content_end-1] == b'\n' {
                    content_end -= 1;
                }
                
                if content_start < content_end {
                    form_data.file_data = Some(part[content_start..content_end].to_vec());
                }
            }
            else if headers_str.contains(r#"name="handle_as""#) {
                let mut content_end = part.len();
                
                if content_end >= 2 && &part[content_end-2..content_end] == b"\r\n" {
                    content_end -= 2;
                } else if content_end >= 1 && part[content_end-1] == b'\n' {
                    content_end -= 1;
                }
                
                if content_start < content_end {
                    let handle_as_value = String::from_utf8_lossy(&part[content_start..content_end])
                        .trim()
                        .to_string();
                    form_data.handle_as = Some(handle_as_value);
                }
            }
        }
    }

    form_data
}

fn test_response() -> Response<BoxBody> {
    let json_response = json!({
        "status": "success",
        "message": "Server is working correctly!",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "endpoints": {
            "test": "GET /test - This endpoint",
            "health": "GET /health - Health check",
            "upload": "POST /upload - File upload endpoint"
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(full(json_response.to_string()))
        .unwrap()
}

async fn requests(
    req: Request<IncomingBody>,
) -> std::result::Result<Response<BoxBody>, Infallible> {
    let response = match (req.method(), req.uri().path()) {

        (&hyper::Method::GET, "/test") => {
            println!("🧪 Test endpoint accessed");
            test_response()
        }
        
        (&hyper::Method::POST, "/upload") => {
            let send_type = req
                .headers()
                .get("content-type")
                .and_then(|ct| ct.to_str().ok())
                .unwrap_or("")
                .to_string();

            println!("Upload type: {:?}", req.headers());

            let body = match req.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    return Ok(responses::internal_server_error());
                }
            };

            if send_type.starts_with("multipart/form-data") {
                if let Some(boundary) = extract_boundary(&send_type) {
                    let form_data = parse_multipart_form(&body, &boundary);

                    if let Some(ref file_buffer) = form_data.file_data {
                        if let Err(e) = fs::write("uploaded_file.jpg", file_buffer).await {
                            eprintln!("Failed to save file: {}", e);
                            return Ok(responses::internal_server_error());
                        }
                        println!("✅ File saved successfully! Size: {} bytes", file_buffer.len());
                    } else {
                        println!("❌ No file data found");
                        return Ok(responses::internal_server_error());
                    }

                    if let Some(handle_as) = form_data.handle_as {
                        if handle_as == "comup" || handle_as == "uncup" {
                            println!("⚙️ Handling as: {}", handle_as);
                        } else {
                            return Ok(responses::internal_server_error());
                        }
                    } else {
                        return Ok(responses::internal_server_error());
                    }
                } else {
                    return Ok(responses::internal_server_error());
                }
            } else {
                return Ok(responses::internal_server_error());
            }

            return Ok(responses::ok());
        }

        _ => responses::internal_server_error(),
    };

    Ok(response)
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr: SocketAddr = "0.0.0.0:3000".parse()?;
    let listener = TcpListener::bind(addr).await?;
    println!("🚀 Server listening on http://192.168.148.126:3000");

    loop {
        let (tcp, _peer_addr) = listener.accept().await?;
        let io = TokioIo::new(tcp);

        tokio::task::spawn(async move {
            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service_fn(requests))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
