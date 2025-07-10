use actix_web::{web, HttpRequest, HttpResponse, Result};
use futures::stream::StreamExt;
use log::{info, error, debug};
use std::collections::HashMap;

use crate::error::AppError;
use crate::HTTP_CLIENT;
use crate::config::RegistrySettings;

pub async fn handle_request(
    req: HttpRequest,
    path: web::Path<(String, String, String)>,
) -> Result<HttpResponse, AppError> {
    let registry_settings = req.app_data::<web::Data<RegistrySettings>>().unwrap();
    // 获取路径参数
    let (mut image_name, path_type, reference) = path.into_inner();

    debug!("原始镜像路径: {}", image_name);
    
    // 检查是否需要重新映射注册表
    let (target_registry, remapped_image_name) = get_target_registry(&registry_settings, &image_name);
    if remapped_image_name != image_name {
        debug!("重映射路径: {} -> {}", image_name, remapped_image_name);
        image_name = remapped_image_name;
    }

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

    // 添加认证头
    if let Some(auth) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth.to_str() {
            request_builder = request_builder.header("Authorization", auth_str);
        }
    }

    // 添加所有 Accept 头
    for accept in req.headers().get_all("Accept") {
        if let Ok(accept_str) = accept.to_str() {
            request_builder = request_builder.header("Accept", accept_str);
        }
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
        // GET 请求，使用流式传输响应体
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

// 根据映射配置获取目标注册表和修改后的镜像名称
fn get_target_registry(registry_settings: &RegistrySettings, image_name: &str) -> (String, String) {
    // 默认使用上游注册表
    let default_registry = registry_settings.upstream_registry.clone();
    
    // 如果没有映射配置，直接返回原始信息
    if registry_settings.registry_mapping.is_none() {
        return (default_registry, image_name.to_string());
    }
    
    let registry_mapping = registry_settings.registry_mapping.as_ref().unwrap();
    
    // 检查镜像名称是否包含需要重映射的注册表部分
    for (source_registry, target_registry) in registry_mapping {
        if image_name.starts_with(&format!("{}/", source_registry)) {
            // 找到映射，提取实际镜像路径
            let actual_image_path = image_name[source_registry.len() + 1..].to_string();
            return (target_registry.clone(), actual_image_path);
        }
    }
    
    // 没有找到匹配的映射，返回原始信息
    (default_registry, image_name.to_string())
}
