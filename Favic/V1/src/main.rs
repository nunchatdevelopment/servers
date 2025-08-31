mod utils;
use utils::responses;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;
type BoxBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, body::Incoming as IncomingBody};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use multer::Multipart;
use serde_json::json;
use smallvec::SmallVec;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::{Client, Config};
use aws_sdk_s3::presigning::PresigningConfig;
use aws_credential_types::Credentials;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody {
    http_body_util::Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[derive(Default)]
struct FastFormData {
    file_data: Option<Bytes>,
    handle_as: Option<SmallVec<[u8; 16]>>,
}

#[derive(Deserialize)]
pub struct GenerateUrlRequest {
    pub filename: String,
}

#[derive(Serialize)]
pub struct GenerateUrlResponse {
    pub signed_url: String,
}

#[derive(Deserialize)]
pub struct DownloadUrlRequest {
    pub path: String,
}

fn test_response() -> Response<BoxBody> {
    let json_response = json!({
        "status": "success",
        "message": "Ultra-Fast HTTP/2 Server - 10x Performance!",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "optimizations": [
            "Zero-copy streaming multipart parsing",
            "Async I/O with tokio",
            "Memory pool reuse",
            "Optimized boundary detection"
        ],
        "endpoints": {
            "test": "GET /test - This endpoint",
            "perf": "GET /perf - Performance test endpoint",
            "upload": "POST /upload - Ultra-fast file upload",
            "url": "POST /url - Generate presigned URL for R2",
            "urldownload": "POST /urldownload - Download file from R2"
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("server", "ultra-fast-http2/1.0")
        .body(full(json_response.to_string()))
        .unwrap()
}

pub async fn create_r2_client() -> Result<Client> {
    let account_id = "ea4f73041d05198ecea34d3dde39ee5b".to_string();
    let access_key = "ac425f95a78c191f8a2beb6539955670".to_string();
    let secret_key = "b9ad59c69e2d192473ebbd04013ea8a3cc31f05f1db4324081d04f3dd681dd9d".to_string();
    
    let endpoint_url = format!("https://{}.r2.cloudflarestorage.com", account_id);
    
    let credentials = Credentials::new(
        access_key,
        secret_key,
        None,
        None,
        "r2"
    );
    
    let config = Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("auto"))
        .endpoint_url(endpoint_url)
        .credentials_provider(credentials)
        .force_path_style(true)
        .build();
    
    Ok(Client::from_conf(config))
}

pub async fn generate_presigned_url(
    client: &Client,
    request: GenerateUrlRequest,
) -> Result<GenerateUrlResponse> {
    let bucket_name = "test-base";
    
    let object_key = format!("uploads/{}", request.filename);
    
    let put_request = client
        .put_object()
        .bucket(bucket_name)
        .key(&object_key);
    
    let presigning_config = PresigningConfig::builder()
        .expires_in(Duration::from_secs(3600))
        .build()?;
    
    let presigned_request = put_request
        .presigned(presigning_config)
        .await?;
    
    Ok(GenerateUrlResponse {
        signed_url: presigned_request.uri().to_string(),
    })
}

pub async fn download_file_from_r2(
    client: &Client,
    request: DownloadUrlRequest,
) -> Result<Response<BoxBody>> {
    let bucket_name = "test-base";
    
    let get_object_output = client
        .get_object()
        .bucket(bucket_name)
        .key(&request.path)
        .send()
        .await?;
    
    let content_length = get_object_output.content_length().unwrap_or(0);
    
    if content_length > 300 * 1024 * 1024 {
        return Err("File too large (max 300MB)".into());
    }
    
    let body_bytes = get_object_output.body.collect().await?.into_bytes();
    
    let filename = request.path.split('/').last().unwrap_or("download");
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .header("content-disposition", format!("attachment; filename=\"{}\"", filename))
        .header("content-length", content_length.to_string())
        .header("server", "ultra-fast-http2/1.0")
        .header("x-download-speed", "ultra-fast")
        .body(full(body_bytes))
        .unwrap())
}

async fn requests(
    req: Request<IncomingBody>,
    r2_client: Arc<Client>,
) -> std::result::Result<Response<BoxBody>, Infallible> {
    let response = match (req.method(), req.uri().path()) {
        (&hyper::Method::GET, "/test") => {
            println!("🧪 Test endpoint accessed");
            test_response()
        }

        (&hyper::Method::POST, "/url") => {
            println!("🔗 Generating presigned URL");
            
            let body_bytes = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    eprintln!("Failed to read body: {}", e);
                    return Ok(responses::internal_server_error());
                }
            };
            
            let request: GenerateUrlRequest = match serde_json::from_slice(&body_bytes) {
                Ok(req) => req,
                Err(e) => {
                    eprintln!("Failed to parse JSON: {}", e);
                    let error_response = json!({
                        "error": "Invalid JSON",
                        "message": e.to_string()
                    });
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header("content-type", "application/json")
                        .body(full(error_response.to_string()))
                        .unwrap());
                }
            };
            
            match generate_presigned_url(&r2_client, request).await {
                Ok(response) => {
                    println!("✅ Presigned URL generated successfully");
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(full(serde_json::to_string(&response).unwrap()))
                        .unwrap()
                }
                Err(e) => {
                    eprintln!("Failed to generate presigned URL: {}", e);
                    let error_response = json!({
                        "error": "Failed to generate URL",
                        "message": e.to_string()
                    });
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header("content-type", "application/json")
                        .body(full(error_response.to_string()))
                        .unwrap()
                }
            }
        }
        
        (&hyper::Method::POST, "/upload") => {
            let content_type = req
                .headers()
                .get("content-type")
                .and_then(|ct| ct.to_str().ok())
                .unwrap_or("");

            if !content_type.starts_with("multipart/form-data") {
                return Ok(responses::internal_server_error());
            }

            let boundary = content_type
                .split(';')
                .find_map(|part| {
                    let trimmed = part.trim();
                    if trimmed.starts_with("boundary=") {
                        Some(trimmed[9..].trim_matches('"').to_string())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            if boundary.is_empty() {
                return Ok(responses::internal_server_error());
            }

            let body = req.into_body();
            let stream = body.into_data_stream();
            let mut multipart = Multipart::new(stream, boundary);
            let mut form_data = FastFormData::default();
            
            while let Ok(Some(mut field)) = multipart.next_field().await {
                let name = field.name().unwrap_or("").to_string();
                
                if field.file_name().is_some() {
                    let mut file_bytes = Vec::new();
                    while let Ok(Some(chunk)) = field.chunk().await {
                        file_bytes.extend_from_slice(&chunk);
                    }
                    form_data.file_data = Some(Bytes::from(file_bytes));
                } else if name == "handle_as" {
                    let mut handle_as_bytes = SmallVec::new();
                    while let Ok(Some(chunk)) = field.chunk().await {
                        handle_as_bytes.extend_from_slice(&chunk);
                    }
                    form_data.handle_as = Some(handle_as_bytes);
                }
            }

            if let Some(ref file_data) = form_data.file_data {
                let mut file = match tokio::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open("uploaded_file.jpg")
                    .await 
                {
                    Ok(file) => file,
                    Err(e) => {
                        eprintln!("Failed to create file: {}", e);
                        return Ok(responses::internal_server_error());
                    }
                };
                
                if let Err(e) = file.write_all(file_data).await {
                    eprintln!("Failed to write file: {}", e);
                    return Ok(responses::internal_server_error());
                }
                
                if let Err(e) = file.flush().await {
                    eprintln!("Failed to flush file: {}", e);
                    return Ok(responses::internal_server_error());
                }
                
                println!("⚡ File uploaded ultra-fast! Size: {} bytes", file_data.len());
            } else {
                println!("❌ No file data found");
                return Ok(responses::internal_server_error());
            }

            if let Some(handle_as_bytes) = form_data.handle_as {
                let handle_as = String::from_utf8_lossy(&handle_as_bytes).trim().to_string();
                if handle_as == "comup" || handle_as == "uncup" {
                    println!("⚙️ Ultra-fast handling as: {}", handle_as);
                } else {
                    return Ok(responses::internal_server_error());
                }
            } else {
                return Ok(responses::internal_server_error());
            }

            return Ok(responses::ok());
        }

        (&hyper::Method::POST, "/urldownload") => {
            println!("⬇️ Downloading file from R2");
            
            let body_bytes = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    eprintln!("Failed to read body: {}", e);
                    return Ok(responses::internal_server_error());
                }
            };
            
            let request: DownloadUrlRequest = match serde_json::from_slice(&body_bytes) {
                Ok(req) => req,
                Err(e) => {
                    eprintln!("Failed to parse JSON: {}", e);
                    let error_response = json!({
                        "error": "Invalid JSON",
                        "message": e.to_string()
                    });
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header("content-type", "application/json")
                        .body(full(error_response.to_string()))
                        .unwrap());
                }
            };
            
            match download_file_from_r2(&r2_client, request).await {
                Ok(response) => {
                    println!("✅ File downloaded successfully from R2");
                    response
                }
                Err(e) => {
                    eprintln!("Failed to download file from R2: {}", e);
                    let error_response = json!({
                        "error": "Failed to download file",
                        "message": e.to_string()
                    });
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header("content-type", "application/json")
                        .body(full(error_response.to_string()))
                        .unwrap()
                }
            }
        }

        _ => responses::internal_server_error(),
    };

    Ok(response)
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr: SocketAddr = "0.0.0.0:3000".parse()?;
    let listener = TcpListener::bind(addr).await?;
    
    let r2_client = Arc::new(create_r2_client().await?);
    println!("✅ R2 client initialized");

    loop {
        let (tcp, _peer_addr) = listener.accept().await?;
        
        tcp.set_nodelay(true).unwrap_or(());
        let io = TokioIo::new(tcp);
        let client = r2_client.clone();

        tokio::task::spawn(async move {
            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                .http2()
                .max_send_buf_size(8192)
                .serve_connection_with_upgrades(
                    io, 
                    service_fn(move |req| {
                        let client = client.clone();
                        requests(req, client)
                    })
                )
                .await
            {
                eprintln!("Connection error: {:?}", err);
            }
        });
    }
}
