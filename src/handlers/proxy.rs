use actix_web::{web, HttpRequest, HttpResponse, Result};
use futures::stream::StreamExt;
use log::{info, error, debug, warn};

use crate::error::AppError;
use crate::HTTP_CLIENT;
use crate::config::{Settings, RegistrySettings};
use crate::auth_utils;

pub async fn handle_request(
    req: HttpRequest,
    path: web::Path<(String, String, String)>,
) -> Result<HttpResponse, AppError> {
    let settings = req.app_data::<web::Data<Settings>>().unwrap();
    // 获取路径参数
    let (mut image_name, path_type, reference) = path.into_inner();

    debug!("原始镜像路径: {}", image_name);
    
    // 检查是否需要重新映射注册表
    let (target_registry, remapped_image_name, registry_key) = get_target_registry(&settings.registry, &image_name);
    debug!("注册表映射结果: 原始镜像={}, 目标注册表={}, 映射后镜像={}, 注册表键={}", 
           image_name, target_registry, remapped_image_name, registry_key);
    if remapped_image_name != image_name {
        debug!("重映射路径: {} -> {}", image_name, remapped_image_name);
        image_name = remapped_image_name;
    }
    
    debug!("目标注册表: {}, 注册表键: {}", target_registry, registry_key);

    // 使用常量构建目标URL
    let path = format!("/v2/{image_name}/{path_type}/{reference}");
    
    // 构建请求，根据原始请求的方法选择 HEAD 或 GET
    let target_url = format!("{target_registry}{path}");
    debug!("目标URL: {}", target_url);
    
    let mut request_builder = if req.method() == actix_web::http::Method::HEAD {
        HTTP_CLIENT.head(&target_url)
    } else {
        HTTP_CLIENT.get(&target_url)
    };

    // 处理认证
    // 首先尝试从请求中获取用户认证信息
    let mut authenticated_user = None;

    if settings.auth.enabled {
        if let Some(auth) = req.headers().get("Authorization") {
            if let Ok(auth_str) = auth.to_str() {
                if let Some((username, password)) = auth_utils::parse_basic_auth(auth_str) {
                    let users = &settings.auth.users;
                    if !users.is_empty() {
                        if auth_utils::verify_user(&username, &password, users) {
                            debug!("用户 {} 验证成功", username);
                            authenticated_user = Some(username);
                        }
                    }
                }
            }
        }
    }

    // 如果启用了认证并找到了已认证用户，使用对应的注册表凭据
    if settings.auth.enabled && authenticated_user.is_some() {
        let username = authenticated_user.unwrap();
        
        // 查找用户对此注册表的凭据
        let users = &settings.auth.users;
        if !users.is_empty() {
            debug!("尝试获取用户 {} 对注册表 {} 的凭据", username, registry_key);
            if let Some(registry_cred) = auth_utils::get_registry_credentials(&username, &registry_key, users) {
                info!("使用 {} 用户的 {} 注册表凭据", username, registry_key);
                
                // 获取注册表 API 版本配置
                let api_version = settings.registry.registries
                    .get(&registry_key)
                    .map(|config| config.api_version.clone())
                    .unwrap_or_default(); // 默认为 Auto
                
                debug!("注册表 {} 配置的 API 版本: {:?}", registry_key, api_version);
                
                // 使用通用认证处理
                match auth_utils::authenticate_registry(
                    &target_registry,
                    &registry_key,
                    &target_url,
                    &registry_cred.username,
                    &registry_cred.password,
                    &api_version
                ).await {
                    auth_utils::RegistryAuthResult::BasicAuth(auth_header) => {
                        info!("使用 Basic Auth 认证");
                        request_builder = request_builder.header("Authorization", auth_header);
                    },
                    auth_utils::RegistryAuthResult::BearerToken(token) => {
                        info!("使用 Bearer Token 认证");
                        request_builder = request_builder.header("Authorization", format!("Bearer {}", token));
                    },
                    auth_utils::RegistryAuthResult::NoAuth => {
                        info!("无需认证");
                        // 不添加认证头
                    },
                    auth_utils::RegistryAuthResult::Failed(error) => {
                        warn!("认证失败: {}，使用原始认证头", error);
                        if let Some(auth) = req.headers().get("Authorization") {
                            if let Ok(auth_str) = auth.to_str() {
                                request_builder = request_builder.header("Authorization", auth_str);
                            }
                        }
                    }
                }
            } else {
                warn!("用户 {} 没有 {} 注册表的凭据", username, registry_key);
                
                // 如果用户提供了认证头，但没有对应注册表的凭据，仍使用原始认证头
                if let Some(auth) = req.headers().get("Authorization") {
                    if let Ok(auth_str) = auth.to_str() {
                        info!("使用客户端原始 Authorization 头: {}", auth_str);
                        request_builder = request_builder.header("Authorization", auth_str);
                    }
                }
            }
        }
    } else {
        debug!("认证已禁用或用户未认证，透传原始认证头");
        // 如果未启用认证或未找到已认证用户，透传原始认证头
        if let Some(auth) = req.headers().get("Authorization") {
            if let Ok(auth_str) = auth.to_str() {
                info!("透传客户端原始 Authorization 头: {}", auth_str);
                request_builder = request_builder.header("Authorization", auth_str);
            }
        } else {
            info!("没有 Authorization 头需要透传");
        }
    }

    // 添加所有 Accept 头，对于 v2 API 注册表添加现代格式支持
    let has_accept = req.headers().contains_key("Accept");
    for accept in req.headers().get_all("Accept") {
        if let Ok(accept_str) = accept.to_str() {
            request_builder = request_builder.header("Accept", accept_str);
        }
    }
    
    // 如果没有 Accept 头，根据注册表 API 版本添加默认值
    if !has_accept {
        let api_version = settings.registry.registries
            .get(&registry_key)
            .map(|config| config.api_version.clone())
            .unwrap_or_default();
        
        let default_accept = match api_version {
            crate::config::RegistryApiVersion::V2 | crate::config::RegistryApiVersion::Auto => {
                // V2 API: 支持现代格式包括 OCI
                "application/vnd.oci.image.manifest.v1+json,application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v1+prettyjws"
            },
            crate::config::RegistryApiVersion::V1 => {
                // V1 API: 只支持传统格式
                "application/vnd.docker.distribution.manifest.v1+prettyjws,application/json"
            }
        };
        
        debug!("为注册表 {} 添加默认 Accept 头: {}", registry_key, default_accept);
        request_builder = request_builder.header("Accept", default_accept);
    }

    // 发送请求到 Docker Registry
    let method = req.method().as_str();
    let response = match request_builder.send().await {
        Ok(resp) => {
            info!("{} {} {:?} {} {}", 
                method, 
                target_url, 
                req.version(),
                resp.status().as_u16(), 
                resp.status().canonical_reason().unwrap_or("Unknown"));
            resp
        },
        Err(e) => {
            error!("{} {} {:?} 失败: {}", method, target_url, req.version(), e);
            return Ok(HttpResponse::InternalServerError()
                .body(format!("无法连接到 Docker Registry: {e}")))
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

    // 记录响应日志
    info!("{} {} {:?} {} {}", 
        req.method(), 
        req.uri(), 
        req.version(),
        status.as_u16(), 
        status.canonical_reason().unwrap_or("Unknown"));

    // 根据请求方法处理响应
    if req.method() == actix_web::http::Method::HEAD {
        // HEAD 请求，不需要返回响应体
        Ok(builder.finish())
    } else {
        // GET 请求
        if !status.is_success() {
            // 非成功响应，打印响应内容
            match response.text().await {
                Ok(body) => {
                    error!("GET 请求失败 ({}): 响应内容: {}", status.as_u16(), body);
                    Ok(builder.body(body))
                },
                Err(e) => {
                    error!("读取失败响应内容时出错: {}", e);
                    Ok(builder.body(format!("无法读取响应内容: {}", e)))
                }
            }
        } else {
            // 成功响应，使用流式传输响应体
            let stream = response
                .bytes_stream()
                .map(|result| {
                    result.map_err(|err| {
                        error!("流读取错误: {}", err);
                        actix_web::error::ErrorInternalServerError(err)
                    })
                });
                
            Ok(builder.streaming(stream))
        }
    }
}

// 根据注册表配置获取目标注册表和修改后的镜像名称
fn get_target_registry(registry_settings: &RegistrySettings, image_name: &str) -> (String, String, String) {
    // 默认使用上游注册表
    let default_registry = registry_settings.upstream_registry.clone();
    let default_registry_key = "docker.io".to_string();
    
    // 如果没有注册表配置，直接返回原始信息
    if registry_settings.registries.is_empty() {
        return (default_registry, image_name.to_string(), default_registry_key);
    }
    
    let registries = &registry_settings.registries;
    
    // 检查镜像名称是否包含需要重映射的注册表部分
    for (registry_key, registry_config) in registries {
        if image_name.starts_with(&format!("{}/", registry_key)) {
            // 找到匹配的注册表，提取实际镜像路径
            let actual_image_path = image_name[registry_key.len() + 1..].to_string();
            return (registry_config.url.clone(), actual_image_path, registry_key.clone());
        }
    }
    
    // 没有找到匹配的映射，返回原始信息
    (default_registry, image_name.to_string(), default_registry_key)
}
