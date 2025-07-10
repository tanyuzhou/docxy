use actix_web::{web, HttpRequest, HttpResponse, Result};
use std::collections::HashMap;
use log::{info, debug, error, warn};
use serde_json::json;

use crate::error::AppError;
use crate::HTTP_CLIENT;
use crate::config::{Settings, RegistryConfig};
use crate::auth_utils;

// 获取 Token 的处理函数
pub async fn get_token(req: HttpRequest) -> Result<HttpResponse, AppError> {
    let settings = req.app_data::<web::Data<Settings>>().unwrap();
    
    // 1. 尝试解析查询参数，失败则返回 400
    let query_params = match web::Query::<HashMap<String, String>>::from_query(req.query_string()) {
        Ok(q) => q,
        Err(_) => {
            return Err(AppError::InvalidRequest("无效的查询参数".to_string()));
        }
    };

    // 检查自定义认证是否启用
    if settings.auth.enabled {
        return handle_custom_auth(req.clone(), &settings, query_params).await;
    }
    
    // 如果未启用自定义认证，则使用默认的 Docker Hub 认证转发
    handle_default_auth(&settings, &query_params, &req).await
}

// 处理自定义认证逻辑
async fn handle_custom_auth(
    req: HttpRequest, 
    settings: &Settings,
    query_params: web::Query<HashMap<String, String>>
) -> Result<HttpResponse, AppError> {
    // 解析认证头
    let username = match req.headers().get("Authorization") {
        Some(auth_header) => {
            if let Ok(auth_str) = auth_header.to_str() {
                // 解析 Basic 认证
                if let Some((user, password)) = auth_utils::parse_basic_auth(auth_str) {
                    // 验证用户名和密码
                    let users = &settings.auth.users;
                    if !users.is_empty() {
                        if auth_utils::verify_user(&user, &password, users) {
                            debug!("用户 {} 验证成功", user);
                            Some(user)
                        } else {
                            warn!("用户 {} 认证失败: 密码不正确", user);
                            return Ok(HttpResponse::Unauthorized()
                                .append_header(("WWW-Authenticate", "Basic realm=\"Docxy Registry\""))
                                .body("认证失败: 用户名或密码不正确"));
                        }
                    } else {
                        warn!("没有配置用户");
                        return Ok(HttpResponse::Unauthorized()
                            .append_header(("WWW-Authenticate", "Basic realm=\"Docxy Registry\""))
                            .body("认证失败: 没有配置用户"));
                    }
                } else {
                    warn!("无法解析 Basic 认证头");
                    return Ok(HttpResponse::Unauthorized()
                        .append_header(("WWW-Authenticate", "Basic realm=\"Docxy Registry\""))
                        .body("认证失败: 认证格式不正确"));
                }
            } else {
                warn!("无法读取认证头");
                return Ok(HttpResponse::Unauthorized()
                    .append_header(("WWW-Authenticate", "Basic realm=\"Docxy Registry\""))
                    .body("认证失败: 认证头格式不正确"));
            }
        },
        None => {
            // 没有认证头，返回 401
            return Ok(HttpResponse::Unauthorized()
                .append_header(("WWW-Authenticate", "Basic realm=\"Docxy Registry\""))
                .body("认证失败: 需要认证"));
        }
    };

    if let Some(user) = username {
        // 检查是否有 scope 参数，判断需要访问哪个注册表
        if let Some(scope) = query_params.get("scope") {
            // 从 scope 中提取注册表信息
            if let Some(registry_key) = extract_registry_from_scope(scope) {
                info!("从 scope {} 提取到注册表: {}", scope, registry_key);
                
                // 查找用户对此注册表的凭据
                let users = &settings.auth.users;
                if !users.is_empty() {
                    if let Some(registry_cred) = auth_utils::get_registry_credentials(&user, &registry_key, users) {
                        info!("用户 {} 有 {} 注册表的凭据，尝试获取上游 token", user, registry_key);
                        
                        // 获取注册表配置
                        let registries = &settings.registry.registries;
                        if !registries.is_empty() {
                            if let Some(registry_config) = registries.get(&registry_key) {
                                // 为 v2 注册表获取上游 token
                                if matches!(registry_config.api_version, crate::config::RegistryApiVersion::V2) {
                                    return get_upstream_v2_token(
                                        registry_config,
                                        registry_cred,
                                        scope,
                                        &query_params
                                    ).await;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // 如果没有找到特定的注册表配置，生成本地 token
        let scopes = match query_params.get("scope") {
            Some(scope) => auth_utils::parse_scope(scope),
            None => Vec::new(),
        };

        let token_response = auth_utils::generate_docker_token(&user, &scopes);
        return Ok(HttpResponse::Ok()
            .content_type("application/json")
            .json(token_response));
    }

    // 不应该到达这里
    Ok(HttpResponse::InternalServerError().body("认证处理错误"))
}

// 处理默认认证（未启用自定义认证时）
async fn handle_default_auth(
    _settings: &Settings,
    query_params: &web::Query<HashMap<String, String>>,
    req: &HttpRequest
) -> Result<HttpResponse, AppError> {
    // 构建 Docker Hub 认证服务 URL
    let mut auth_url = reqwest::Url::parse("https://auth.docker.io/token").unwrap();
    {
        let mut query_pairs = auth_url.query_pairs_mut();
        // service 必须是 registry.docker.io
        query_pairs.append_pair("service", "registry.docker.io");

        // 透传所有客户端提供的查询参数（包含 account、client_id、offline_token、scope 等）
        // 避免重复 service
        for (k, v) in query_params.iter() {
            if k != "service" {
                query_pairs.append_pair(k, v);
            }
        }
    }

    info!("转发 token 请求至: {}", auth_url);

    // 构造向上游的请求构建器
    let mut request_builder = HTTP_CLIENT.get(auth_url.clone());

    // 检查并代理 Authorization 头
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            info!("代理 Authorization 头: {}", auth_str);
            request_builder = request_builder.header("Authorization", auth_str);
        }
    }

    // 发送请求到 Docker Hub 认证服务
    let response = match request_builder.send().await {
        Ok(resp) => {
            info!("GET {} {:?} {} {}", 
                auth_url, 
                req.version(), 
                resp.status().as_u16(), 
                resp.status().canonical_reason().unwrap_or("Unknown"));
            resp
        },
        Err(e) => {
            error!("GET {} {:?} 失败: {}", auth_url, req.version(), e);
            return Ok(HttpResponse::InternalServerError()
                .body("无法连接到 Docker Hub 认证服务"))
        }
    };

    // 获取状态码和响应头
    let status = response.status();
    let mut builder = HttpResponse::build(actix_web::http::StatusCode::from_u16(status.as_u16()).unwrap());

    // 复制所有响应头
    for (name, value) in response.headers() {
        if let Ok(value_str) = value.to_str() {
            builder.append_header((name.as_str(), value_str));
        }
    }

    // 获取响应体并返回
    match response.bytes().await {
        Ok(bytes) => {
            info!("{} {} {:?} {} {}", 
                req.method(), 
                req.uri(), 
                req.version(),
                status.as_u16(), 
                status.canonical_reason().unwrap_or("Unknown"));
            Ok(builder.body(bytes))
        },
        Err(e) => {
            error!("读取认证服务响应失败: {}", e);
            Ok(HttpResponse::InternalServerError().body("无法读取认证服务响应"))
        }
    }
}

// 为 v2 注册表获取上游 token
async fn get_upstream_v2_token(
    registry_config: &RegistryConfig,
    registry_cred: &crate::config::RegistryCredential,
    scope: &str,
    query_params: &web::Query<HashMap<String, String>>
) -> Result<HttpResponse, AppError> {
    // 确定认证 URL
    let auth_url = registry_config.auth_url
        .as_ref()
        .map(|url| url.clone())
        .unwrap_or_else(|| format!("{}/token", registry_config.url));
    
    info!("向上游注册表请求 token: {}", auth_url);
    
    // 构建请求参数
    let mut url = reqwest::Url::parse(&auth_url)
        .map_err(|e| AppError::InvalidRequest(format!("无效的认证 URL: {}", e)))?;
    
    {
        let mut query_pairs = url.query_pairs_mut();
        
        // 添加基本参数
        if let Some(service) = query_params.get("service") {
            query_pairs.append_pair("service", service);
        }
        query_pairs.append_pair("scope", scope);
        
        // 透传其他参数
        for (key, value) in query_params.iter() {
            if key != "service" && key != "scope" {
                query_pairs.append_pair(key, value);
            }
        }
    }
    
    // 创建认证头
    let auth_header = auth_utils::create_basic_auth(&registry_cred.username, &registry_cred.password);
    
    // 发送请求到上游认证服务
    let response = match HTTP_CLIENT
        .get(url.as_str())
        .header("Authorization", auth_header)
        .send()
        .await
    {
        Ok(resp) => {
            info!("上游 token 请求响应: {}", resp.status());
            resp
        },
        Err(e) => {
            error!("上游 token 请求失败: {}", e);
            return Ok(HttpResponse::InternalServerError()
                .body("无法连接到上游认证服务"));
        }
    };
    
    // 转发响应
    let status = response.status();
    let mut builder = HttpResponse::build(actix_web::http::StatusCode::from_u16(status.as_u16()).unwrap());
    
    // 复制响应头
    for (name, value) in response.headers() {
        if let Ok(value_str) = value.to_str() {
            builder.append_header((name.as_str(), value_str));
        }
    }
    
    // 获取响应体
    match response.bytes().await {
        Ok(bytes) => Ok(builder.body(bytes)),
        Err(e) => {
            error!("读取上游认证响应失败: {}", e);
            Ok(HttpResponse::InternalServerError().body("无法读取上游认证响应"))
        }
    }
}

// 从 scope 中提取注册表名称
fn extract_registry_from_scope(scope: &str) -> Option<String> {
    // scope 格式通常是: repository:namespace/repo:pull,push
    // 对于 ghcr.io: repository:user/repo:pull
    // 对于 docker.io: repository:user/repo:pull
    
    if scope.starts_with("repository:") {
        let repo_part = &scope[11..]; // 跳过 "repository:"
        
        // 检查是否包含明确的注册表前缀
        if repo_part.contains("/") {
            let parts: Vec<&str> = repo_part.split('/').collect();
            if parts.len() >= 2 {
                let first_part = parts[0];
                
                // 如果第一部分包含点号，可能是注册表域名
                if first_part.contains('.') {
                    return Some(first_part.to_string());
                }
                
                // 检查是否是已知的命名空间模式
                // GitHub Container Registry 使用用户名/组织名作为命名空间
                // 但没有明确的注册表前缀，需要通过其他方式判断
            }
        }
    }
    
    // 默认返回 None，让调用者决定如何处理
    None
}

// 处理 /v2/ 路径的认证挑战
pub async fn proxy_challenge(req: HttpRequest) -> Result<HttpResponse, AppError> {
    let settings = req.app_data::<web::Data<Settings>>().unwrap();

    // 检查是否启用自定义认证
    if settings.auth.enabled {
        // 首先检查客户端是否提供了认证头
        if let Some(auth_header) = req.headers().get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                // 解析 Basic 认证
                if let Some((username, password)) = auth_utils::parse_basic_auth(auth_str) {
                    // 验证用户名和密码
                    let users = &settings.auth.users;
                    if !users.is_empty() {
                        if auth_utils::verify_user(&username, &password, users) {
                            info!("用户 {} 认证成功，允许访问 /v2/", username);
                            // 认证成功，返回 200 OK
                            return Ok(HttpResponse::Ok()
                                .json(json!({})));
                        } else {
                            warn!("用户 {} 认证失败: 密码不正确", username);
                        }
                    } else {
                        warn!("没有配置用户");
                    }
                } else {
                    warn!("无法解析 Basic 认证头");
                }
            } else {
                warn!("无法读取认证头");
            }
        }
        
        // 认证失败或没有认证头，发送认证挑战
        info!("发送Basic认证挑战");
        return Ok(HttpResponse::Unauthorized()
            .append_header(("WWW-Authenticate", "Basic realm=\"Docker Registry\""))
            .body(json!({
                "errors": [{
                    "code": "UNAUTHORIZED",
                    "message": "authentication required",
                    "detail": null
                }]
            }).to_string()));
    }

    // 如果未启用自定义认证，则使用默认的代理认证挑战
    let upstream_registry = &settings.registry.upstream_registry;
    let host = match req.connection_info().host() {
        host if host.contains(':') => host.to_string(),
        host => host.to_string()
    };
    let request_url = format!("{upstream_registry}/v2/");
    
    // 构建请求，检查是否有 Authorization 头
    let mut request_builder = HTTP_CLIENT.get(&request_url);
    
    // 如果客户端提供了 Authorization 头，转发给上游
    if let Some(auth) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth.to_str() {
            info!("代理 Authorization 头到 /v2/: {}", auth_str);
            request_builder = request_builder.header("Authorization", auth_str);
        }
    }

    let response = match request_builder.send().await {
        Ok(resp) => {
            info!("GET {} {:?} {} {}", 
                request_url,
                req.version(), 
                resp.status().as_u16(), 
                resp.status().canonical_reason().unwrap_or("Unknown"));
            resp
        },
        Err(e) => {
            error!("GET {} {:?} 失败: {}", request_url, req.version(), e);
            return Ok(HttpResponse::InternalServerError()
                      .body("无法连接到上游 Docker Registry"))
        }
    };

    let status = response.status().as_u16();
    let mut builder = HttpResponse::build(actix_web::http::StatusCode::from_u16(status).unwrap());

    // 只有在返回 401 时才设置 WWW-Authenticate 头
    if status == 401 {
        let protocol = if settings.server.https_enabled { "https" } else { "http" };
        let auth_header = format!(
            "Bearer realm=\"{}://{}/auth/token\",service=\"registry.docker.io\"",
            protocol, host
        );
        info!("设置认证头: {}", auth_header);
        
        builder.append_header((
            "WWW-Authenticate",
            auth_header
        ));
    }

    let body = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            error!("读取上游响应内容失败: {}", e);
            String::from("无法读取上游响应内容")
        }
    };

    info!("{} {} {:?} {} {}", 
        req.method(), 
        req.uri(), 
        req.version(),
        status, 
        actix_web::http::StatusCode::from_u16(status).unwrap().canonical_reason().unwrap_or("Unknown"));
    
    Ok(builder.body(body))
}
