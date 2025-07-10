use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use log::error;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::config::{UserSettings, RegistryCredential, RegistryApiVersion};

// JWT token structure returned to Docker clients
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
    pub access_token: String,
    pub expires_in: u64,
    pub issued_at: String,
}

// Basic auth credentials parser
pub fn parse_basic_auth(auth_header: &str) -> Option<(String, String)> {
    // Basic auth format: "Basic base64(username:password)"
    if !auth_header.starts_with("Basic ") {
        return None;
    }
    
    let credentials = auth_header.trim_start_matches("Basic ").trim();
    match BASE64.decode(credentials) {
        Ok(decoded) => {
            match String::from_utf8(decoded) {
                Ok(auth_str) => {
                    let parts: Vec<&str> = auth_str.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        Some((parts[0].to_string(), parts[1].to_string()))
                    } else {
                        None
                    }
                },
                Err(e) => {
                    error!("无法解析认证字符串: {}", e);
                    None
                }
            }
        },
        Err(e) => {
            error!("无法解码 Base64 认证: {}", e);
            None
        }
    }
}

// Verify user credentials against configured users
pub fn verify_user(username: &str, password: &str, users: &HashMap<String, UserSettings>) -> bool {
    match users.get(username) {
        Some(user) => user.password == password,
        None => false
    }
}

// Get registry credentials for a user and registry
pub fn get_registry_credentials<'a>(username: &str, registry: &str, users: &'a HashMap<String, UserSettings>) -> Option<&'a RegistryCredential> {
    log::debug!("查找用户 {} 对注册表 {} 的凭据", username, registry);
    
    if let Some(user) = users.get(username) {
        log::debug!("找到用户 {}", username);
        
        let creds = &user.registry_credentials;
        if !creds.is_empty() {
            log::debug!("用户 {} 有注册表凭据配置，可用的注册表: {:?}", username, creds.keys().collect::<Vec<_>>());
            
            if let Some(registry_cred) = creds.get(registry) {
                log::debug!("找到用户 {} 对注册表 {} 的凭据", username, registry);
                return Some(registry_cred);
            } else {
                log::debug!("用户 {} 没有注册表 {} 的凭据", username, registry);
            }
        } else {
            log::debug!("用户 {} 没有任何注册表凭据配置", username);
        }
    } else {
        log::debug!("找不到用户 {}", username);
    }
    
    None
}

// Create a Base64 encoded Basic auth header
pub fn create_basic_auth(username: &str, password: &str) -> String {
    let auth_str = format!("{}:{}", username, password);
    format!("Basic {}", BASE64.encode(auth_str.as_bytes()))
}



// Simple JWT generation for Docker Registry authentication
// In a production system, you might want to use a proper JWT library
pub fn generate_docker_token(username: &str, scopes: &[String]) -> TokenResponse {
    use chrono::{Utc, Duration};
    use serde_json::json;
    use sha2::{Sha256, Digest};
    
    let now = Utc::now();
    let issued_at = now.to_rfc3339();
    let expiry = now + Duration::hours(1);
    
    // Create a simple JWT token
    // Header: {"alg": "HS256", "typ": "JWT"}
    let header = BASE64.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    
    // Create payload with Docker Registry expected claims
    let claims = json!({
        "iss": "docxy",
        "sub": username,
        "aud": "registry.docker.io",
        "exp": expiry.timestamp(),
        "nbf": now.timestamp(),
        "iat": now.timestamp(),
        "jti": format!("{:x}", Sha256::digest(username.as_bytes())),
        "access": scopes.iter().map(|s| {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() >= 3 {
                json!({
                    "type": parts[0],
                    "name": parts[1],
                    "actions": parts[2].split(',').collect::<Vec<&str>>()
                })
            } else {
                json!({
                    "type": "repository",
                    "name": s,
                    "actions": ["pull"]
                })
            }
        }).collect::<Vec<_>>()
    });
    
    let payload = BASE64.encode(claims.to_string());
    
    // In production, you should use a proper HMAC
    // Here we just concatenate for simplicity
    let digest = Sha256::digest(format!("{}.{}", header, payload).as_bytes());
    let digest_hex = digest.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let signature = BASE64.encode(format!("docxy-signature-{}", digest_hex));
    
    let token = format!("{}.{}.{}", header, payload, signature);
    
    TokenResponse {
        token: token.clone(),
        access_token: token,
        expires_in: 3600,
        issued_at,
    }
}

// Parse scope parameter from Docker Registry requests
pub fn parse_scope(scope: &str) -> Vec<String> {
    scope.split(' ').map(String::from).collect()
}

// Docker Registry v2 token response structure
#[derive(Debug, Deserialize)]
pub struct RegistryTokenResponse {
    pub token: Option<String>,
    pub access_token: Option<String>,
}

// Parse WWW-Authenticate header to extract auth parameters
#[derive(Debug)]
pub struct AuthChallenge {
    pub realm: String,
    pub service: String,
    pub scope: Option<String>,
}

pub fn parse_www_authenticate(www_auth: &str) -> Option<AuthChallenge> {
    if !www_auth.starts_with("Bearer ") {
        return None;
    }
    
    let params = &www_auth[7..]; // 跳过 "Bearer "
    
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    
    // 简单解析参数
    for param in params.split(',') {
        let param = param.trim();
        if let Some(eq_pos) = param.find('=') {
            let key = param[..eq_pos].trim();
            let value = param[eq_pos + 1..].trim().trim_matches('"');
            
            match key {
                "realm" => realm = Some(value.to_string()),
                "service" => service = Some(value.to_string()),
                "scope" => scope = Some(value.to_string()),
                _ => {}
            }
        }
    }
    
    if let (Some(realm), Some(service)) = (realm, service) {
        Some(AuthChallenge { realm, service, scope })
    } else {
        None
    }
}

// Get Docker Registry v2 bearer token
pub async fn get_registry_v2_token(
    username: &str,
    password: &str,
    challenge: &AuthChallenge,
) -> Result<String, String> {
    use reqwest;
    
    log::debug!("获取 Registry v2 Bearer token，realm: {}, service: {}, scope: {:?}", 
        challenge.realm, challenge.service, challenge.scope);
    
    // 构建认证URL
    let mut auth_url = format!("{}?service={}", challenge.realm, challenge.service);
    if let Some(scope) = &challenge.scope {
        auth_url.push_str(&format!("&scope={}", scope));
    }
    
    // 创建 Basic 认证头
    let auth_header = create_basic_auth(username, password);
    
    // 发送请求
    let client = reqwest::Client::new();
    let response = client
        .get(&auth_url)
        .header("Authorization", auth_header)
        .send()
        .await
        .map_err(|e| format!("请求 Registry token 失败: {}", e))?;
    
    if response.status().is_success() {
        let token_response: RegistryTokenResponse = response
            .json()
            .await
            .map_err(|e| format!("解析 Registry token 响应失败: {}", e))?;
        
        let token = token_response.token
            .or(token_response.access_token)
            .ok_or_else(|| "响应中没有找到 token".to_string())?;
        
        log::debug!("成功获取 Registry v2 Bearer token");
        Ok(token)
    } else {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_else(|_| "未知错误".to_string());
        Err(format!("Registry token 请求失败 ({}): {}", status, error_text))
    }
}

// Handle registry authentication based on API version
pub async fn handle_registry_auth(
    registry_cred: &RegistryCredential,
    api_version: &RegistryApiVersion,
    target_url: &str,
) -> Result<String, String> {
    match api_version {
        RegistryApiVersion::V1 => {
            // V1 使用 Basic Auth
            Ok(create_basic_auth(&registry_cred.username, &registry_cred.password))
        },
        RegistryApiVersion::V2 => {
            // V2 需要 token challenge 流程
            log::debug!("尝试 Registry v2 token challenge 流程");
            
            // 1. 先发送一个请求获取 WWW-Authenticate 头
            let client = reqwest::Client::new();
            let response = client.get(target_url).send().await
                .map_err(|e| format!("获取认证挑战失败: {}", e))?;
            
            if response.status() == 401 {
                if let Some(www_auth) = response.headers().get("WWW-Authenticate") {
                    if let Ok(www_auth_str) = www_auth.to_str() {
                        if let Some(challenge) = parse_www_authenticate(www_auth_str) {
                            // 2. 获取 Bearer token
                            let bearer_token = get_registry_v2_token(
                                &registry_cred.username,
                                &registry_cred.password,
                                &challenge,
                            ).await?;
                            
                            return Ok(format!("Bearer {}", bearer_token));
                        } else {
                            log::warn!("无法解析 WWW-Authenticate 头: {}", www_auth_str);
                        }
                    }
                } else {
                    log::warn!("401 响应但没有 WWW-Authenticate 头");
                }
            } else if response.status().is_success() {
                // 不需要认证
                log::debug!("Registry 不需要认证");
                return Ok(String::new());
            }
            
            // 如果 token challenge 失败，回退到 Basic Auth
            log::warn!("Token challenge 失败，回退到 Basic Auth");
            Ok(create_basic_auth(&registry_cred.username, &registry_cred.password))
        },
        RegistryApiVersion::Auto => {
            // Auto 模式：先尝试 V2，失败则回退到 V1
            log::debug!("Auto 模式：先尝试 V2 token challenge");
            
            // 先尝试 V2 认证
            log::debug!("尝试 Registry v2 token challenge 流程");
            
            // 1. 先发送一个请求获取 WWW-Authenticate 头
            let client = reqwest::Client::new();
            let response = client.get(target_url).send().await
                .map_err(|e| format!("获取认证挑战失败: {}", e))?;
            
            if response.status() == 401 {
                if let Some(www_auth) = response.headers().get("WWW-Authenticate") {
                    if let Ok(www_auth_str) = www_auth.to_str() {
                        if let Some(challenge) = parse_www_authenticate(www_auth_str) {
                            // 2. 获取 Bearer token
                            match get_registry_v2_token(
                                &registry_cred.username,
                                &registry_cred.password,
                                &challenge,
                            ).await {
                                Ok(bearer_token) => {
                                    log::debug!("Auto 模式 V2 认证成功");
                                    return Ok(format!("Bearer {}", bearer_token));
                                },
                                Err(e) => {
                                    log::warn!("Auto 模式 V2 认证失败，回退到 V1: {}", e);
                                }
                            }
                        } else {
                            log::warn!("无法解析 WWW-Authenticate 头: {}", www_auth_str);
                        }
                    }
                } else {
                    log::warn!("401 响应但没有 WWW-Authenticate 头");
                }
            } else if response.status().is_success() {
                // 不需要认证
                log::debug!("Auto 模式：注册表不需要认证");
                return Ok(String::new());
            }
            
            // 如果 V2 失败，回退到 V1 Basic Auth
            log::warn!("Auto 模式回退到 V1 Basic Auth");
            Ok(create_basic_auth(&registry_cred.username, &registry_cred.password))
        }
    }
}

// Registry authentication result
#[derive(Debug)]
pub enum RegistryAuthResult {
    BasicAuth(String),      // Authorization header value
    BearerToken(String),    // Bearer token
    NoAuth,                 // No authentication needed
    Failed(String),         // Authentication failed with error message
}

// Auto-detect registry API version by probing /v2/ endpoint
pub async fn detect_registry_api_version(registry_url: &str) -> RegistryApiVersion {
    use reqwest;
    
    log::debug!("自动检测注册表 API 版本: {}", registry_url);
    
    let client = reqwest::Client::new();
    let v2_url = format!("{}/v2/", registry_url.trim_end_matches('/'));
    
    match client.get(&v2_url).send().await {
        Ok(response) => {
            let status = response.status();
            log::debug!("V2 API 探测响应: {}", status);
            
            // Check if it has Docker Registry v2 API indicators
            if status == 200 || status == 401 || status == 403 {
                // Check for v2 API specific headers
                if let Some(www_auth) = response.headers().get("WWW-Authenticate") {
                    if let Ok(auth_str) = www_auth.to_str() {
                        if auth_str.contains("Bearer") {
                            log::info!("检测到 Docker Registry v2 API (Bearer 认证)");
                            return RegistryApiVersion::V2;
                        }
                    }
                }
                
                // Check for Docker-Distribution-Api-Version header
                if response.headers().get("Docker-Distribution-Api-Version").is_some() {
                    log::info!("检测到 Docker Registry v2 API (Distribution header)");
                    return RegistryApiVersion::V2;
                }
                
                // If 200 OK without auth headers, likely v2
                if status == 200 {
                    log::info!("检测到 Docker Registry v2 API (200 OK)");
                    return RegistryApiVersion::V2;
                }
            }
            
            log::info!("未能确定 API 版本，默认使用 v1");
            RegistryApiVersion::V1
        },
        Err(e) => {
            log::warn!("API 版本检测失败 {}: {}，默认使用 v1", registry_url, e);
            RegistryApiVersion::V1
        }
    }
}

// Generic registry authentication handler
pub async fn authenticate_registry(
    registry_url: &str,
    registry_key: &str,
    target_url: &str,
    username: &str,
    password: &str,
    api_version: &RegistryApiVersion
) -> RegistryAuthResult {
    let effective_version = match api_version {
        RegistryApiVersion::Auto => detect_registry_api_version(registry_url).await,
        version => version.clone(),
    };
    
    log::debug!("使用 API 版本 {:?} 认证注册表 {}", effective_version, registry_key);
    
    match effective_version {
        RegistryApiVersion::V1 => {
            // V1 API: Use Basic Auth directly
            log::debug!("使用 v1 API Basic 认证");
            let auth_header = create_basic_auth(username, password);
            RegistryAuthResult::BasicAuth(auth_header)
        },
        RegistryApiVersion::V2 => {
            // V2 API: Try Bearer token flow with proper token challenge
            log::debug!("使用 v2 API Bearer token 认证");
            
            match handle_registry_auth(
                &RegistryCredential {
                    username: username.to_string(),
                    password: password.to_string(),
                },
                &RegistryApiVersion::V2,
                target_url,
            ).await {
                Ok(auth_header) => {
                    if auth_header.is_empty() {
                        RegistryAuthResult::NoAuth
                    } else if auth_header.starts_with("Bearer ") {
                        let token = auth_header[7..].to_string(); // 移除 "Bearer " 前缀
                        RegistryAuthResult::BearerToken(token)
                    } else {
                        RegistryAuthResult::BasicAuth(auth_header)
                    }
                },
                Err(e) => {
                    log::warn!("V2 认证失败: {}", e);
                    RegistryAuthResult::Failed(e)
                }
            }
        },
        RegistryApiVersion::Auto => {
            // This should not happen due to the match above
            log::error!("意外的 Auto 版本");
            RegistryAuthResult::Failed("API 版本检测错误".to_string())
        }
    }
}