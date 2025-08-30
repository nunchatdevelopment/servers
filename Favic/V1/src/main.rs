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
use tokio::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::ptr;
use memmap2::MmapMut;

fn full<T: Into<bytes::Bytes>>(chunk: T) -> BoxBody {
    http_body_util::Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn ultra_fast_boundary_search(data: &[u8], boundary: &[u8]) -> Vec<usize> {
    let mut positions = Vec::new();
    if boundary.is_empty() || data.len() < boundary.len() {
        return positions;
    }
    
    let mut i = 0;
    let boundary_len = boundary.len();
    let data_len = data.len();
    
    while i <= data_len - boundary_len {
        if data[i..i + boundary_len] == *boundary {
            positions.push(i);
            i += boundary_len;
        } else {
            i += 1;
        }
    }
    
    positions
}

struct FormData {
    handle_as: Option<String>,
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
    let (parts, body) = req.into_parts();
    let response = match (parts.method, parts.uri.path()) {
        (&hyper::Method::GET, "/test") => {
            println!("🧪 Test endpoint accessed");
            test_response()
        }
        
        (hyper::Method::POST, "/upload") => {
            let content_type = parts
                .headers
                .get("content-type")
                .and_then(|ct| ct.to_str().ok())
                .unwrap_or("");

            if !content_type.starts_with("multipart/form-data") {
                return Ok(responses::internal_server_error());
            }

            let boundary = content_type
                .split("boundary=")
                .nth(1)
                .and_then(|b| b.split(';').next())
                .map(|b| b.trim_matches('"'))
                .unwrap_or("");

            if boundary.is_empty() {
                return Ok(responses::internal_server_error());
            }

            let body_bytes = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => return Ok(responses::internal_server_error()),
            };
            
            let boundary_bytes = format!("--{}", boundary).into_bytes();
            let positions = ultra_fast_boundary_search(&body_bytes, &boundary_bytes);
            
            if positions.len() < 2 {
                return Ok(responses::internal_server_error());
            }
            
            let mut form_data = FormData { handle_as: None };
            let mut file_saved = false;
            let mut file_data: Option<&[u8]> = None;
            
            for i in 0..positions.len() - 1 {
                let start = positions[i] + boundary_bytes.len();
                let end = positions[i + 1];
                
                if start >= end || start >= body_bytes.len() {
                    continue;
                }
                
                let part = &body_bytes[start..end];
                
                if let Some(header_end) = part.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = &part[..header_end];
                    let content_start = header_end + 4;
                    let mut content_end = part.len();
                    
                    if content_end >= 2 && &part[content_end-2..content_end] == b"\r\n" {
                        content_end -= 2;
                    }
                    
                    let headers_str = unsafe { std::str::from_utf8_unchecked(headers) };
                    
                    if headers_str.contains("filename=") {
                        if content_start < content_end {
                            file_data = Some(&part[content_start..content_end]);
                        }
                    } else if headers_str.contains(r#"name="handle_as""#) {
                        if content_start < content_end {
                            let value = unsafe { std::str::from_utf8_unchecked(&part[content_start..content_end]) }.trim();
                            if value == "comup" || value == "uncup" {
                                form_data.handle_as = Some(value.to_string());
                            } else {
                                return Ok(responses::internal_server_error());
                            }
                        }
                    }
                }
            }
            
            if let Some(file_bytes) = file_data {
                let file_id = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
                let filename = format!("uploaded_file_{}.mp4", file_id);
                
                match std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&filename) {
                    Ok(_file) => {
                        let mut mmap = match MmapMut::map_anon(file_bytes.len()) {
                            Ok(mmap) => mmap,
                            Err(_) => return Ok(responses::internal_server_error()),
                        };
                        
                        unsafe {
                            ptr::copy_nonoverlapping(
                                file_bytes.as_ptr(),
                                mmap.as_mut_ptr(),
                                file_bytes.len()
                            );
                        }
                        
                        if let Err(_) = std::fs::write(&filename, &*mmap) {
                            return Ok(responses::internal_server_error());
                        }
                        
                        println!("⚡ Ultra-fast file saved: {} (Size: {} bytes)", filename, file_bytes.len());
                        file_saved = true;
                    }
                    Err(_) => {
                        return Ok(responses::internal_server_error());
                    }
                }
            }

            if !file_saved {
                println!("❌ No file data found");
                return Ok(responses::internal_server_error());
            }

            if form_data.handle_as.is_none() {
                return Ok(responses::internal_server_error());
            }

            println!("⚙️ Handling as: {:?}", form_data.handle_as);
            Ok(responses::ok())
        }

        _ => Ok(responses::internal_server_error()),
    };

    response
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr: SocketAddr = "0.0.0.0:3000".parse()?;
    let listener = TcpListener::bind(addr).await?;
    println!("Server Running");

    loop {
        let (tcp, _peer_addr) = listener.accept().await?;
        
        tcp.set_nodelay(true).ok();
        
        let io = TokioIo::new(tcp);

        tokio::task::spawn(async move {
            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                .http2()
                .enable_connect_protocol()
                .max_send_buf_size(1024 * 1024)
                .initial_stream_window_size(Some(1024 * 1024))
                .initial_connection_window_size(Some(2 * 1024 * 1024))
                .adaptive_window(true)
                .max_frame_size(Some(16384))
                .serve_connection(io, service_fn(requests))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
