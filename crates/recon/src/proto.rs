use anyhow::{Context, Result};
use nevelio_core::types::{Endpoint, Parameter, ParameterLocation};

/// A discovered gRPC service with its RPC methods.
#[derive(Debug, Clone)]
pub struct GrpcService {
    pub package: String,
    pub name: String,
    pub methods: Vec<GrpcMethod>,
}

#[derive(Debug, Clone)]
pub struct GrpcMethod {
    pub name: String,
    pub input_type: String,
    pub output_type: String,
    pub client_streaming: bool,
    pub server_streaming: bool,
}

/// Parse a `.proto` file and return discovered services.
pub fn parse_proto(path: &str) -> Result<Vec<GrpcService>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read .proto file: {}", path))?;
    Ok(parse_proto_content(&content))
}

/// Convert discovered gRPC services into Nevelio Endpoints for scanning.
/// The convention: path = /Package.ServiceName/MethodName (gRPC URL format)
pub fn services_to_endpoints(base_url: &str, services: &[GrpcService]) -> Vec<Endpoint> {
    let base = base_url.trim_end_matches('/');
    let mut endpoints = Vec::new();

    for svc in services {
        let pkg_prefix = if svc.package.is_empty() {
            svc.name.clone()
        } else {
            format!("{}.{}", svc.package, svc.name)
        };

        for method in &svc.methods {
            let path = format!("/{}/{}", pkg_prefix, method.name);
            let full_url = format!("{}{}", base, path);
            let mut ep = Endpoint {
                method: "POST".to_string(),
                path: path.clone(),
                full_url,
                parameters: vec![],
                auth_required: true,
            };

            // Add a parameter representing the gRPC request body
            ep.parameters.push(Parameter {
                name: "body".to_string(),
                location: ParameterLocation::Body,
                required: true,
                schema: None,
            });

            // Annotate streaming methods
            if method.client_streaming || method.server_streaming {
                ep.parameters.push(Parameter {
                    name: "__streaming".to_string(),
                    location: ParameterLocation::Header,
                    required: false,
                    schema: None,
                });
            }

            endpoints.push(ep);
        }
    }

    endpoints
}

// ---------------------------------------------------------------------------
// Internal parser (regex-free, line-by-line state machine)
// ---------------------------------------------------------------------------

pub fn parse_proto_content(content: &str) -> Vec<GrpcService> {
    let mut services = Vec::new();
    let mut package = String::new();

    let mut in_service = false;
    let mut current_service: Option<GrpcService> = None;
    let mut brace_depth: usize = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }

        // Package declaration
        if trimmed.starts_with("package ") && !in_service {
            package = trimmed
                .strip_prefix("package ")
                .unwrap_or("")
                .trim_end_matches(';')
                .trim()
                .to_string();
            continue;
        }

        // Service block start
        if trimmed.starts_with("service ") {
            let name = trimmed
                .strip_prefix("service ")
                .unwrap_or("")
                .split('{')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();

            in_service = true;
            brace_depth = trimmed.chars().filter(|&c| c == '{').count()
                - trimmed.chars().filter(|&c| c == '}').count();
            current_service = Some(GrpcService {
                package: package.clone(),
                name,
                methods: Vec::new(),
            });
            continue;
        }

        if in_service {
            brace_depth = brace_depth.saturating_add(trimmed.chars().filter(|&c| c == '{').count());
            brace_depth = brace_depth.saturating_sub(trimmed.chars().filter(|&c| c == '}').count());

            // rpc method line: rpc MethodName (InputType) returns (OutputType) { ... }
            if trimmed.starts_with("rpc ") {
                if let Some(method) = parse_rpc_line(trimmed) {
                    if let Some(ref mut svc) = current_service {
                        svc.methods.push(method);
                    }
                }
            }

            if brace_depth == 0 {
                in_service = false;
                if let Some(svc) = current_service.take() {
                    if !svc.methods.is_empty() {
                        services.push(svc);
                    }
                }
            }
        }
    }

    services
}

fn parse_rpc_line(line: &str) -> Option<GrpcMethod> {
    // rpc MethodName (stream? InputType) returns (stream? OutputType) ;
    let after_rpc = line.strip_prefix("rpc ")?.trim();

    // Extract method name (up to first '(')
    let paren_pos = after_rpc.find('(')?;
    let name = after_rpc[..paren_pos].trim().to_string();

    // Extract input type
    let input_section = &after_rpc[paren_pos..];
    let close_paren = input_section.find(')')?;
    let input_raw = input_section[1..close_paren].trim();
    let (client_streaming, input_type) = if input_raw.starts_with("stream ") {
        (
            true,
            input_raw
                .strip_prefix("stream ")
                .unwrap_or(input_raw)
                .trim()
                .to_string(),
        )
    } else {
        (false, input_raw.to_string())
    };

    // Find "returns (...)"
    let after_input = &input_section[close_paren + 1..];
    let returns_pos = after_input.find("returns")?;
    let after_returns = &after_input[returns_pos + "returns".len()..].trim();
    let open_paren = after_returns.find('(')?;
    let close_paren2 = after_returns.find(')')?;
    let output_raw = after_returns[open_paren + 1..close_paren2].trim();
    let (server_streaming, output_type) = if output_raw.starts_with("stream ") {
        (
            true,
            output_raw
                .strip_prefix("stream ")
                .unwrap_or(output_raw)
                .trim()
                .to_string(),
        )
    } else {
        (false, output_raw.to_string())
    };

    Some(GrpcMethod {
        name,
        input_type,
        output_type,
        client_streaming,
        server_streaming,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PROTO: &str = r#"
syntax = "proto3";
package helloworld;

service Greeter {
  rpc SayHello (HelloRequest) returns (HelloReply) {}
  rpc SayHelloAgain (HelloRequest) returns (HelloReply) {}
  rpc StreamGreet (stream HelloRequest) returns (stream HelloReply) {}
}

message HelloRequest {
  string name = 1;
}

message HelloReply {
  string message = 1;
}
"#;

    #[test]
    fn parse_service_name() {
        let services = parse_proto_content(SAMPLE_PROTO);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "Greeter");
        assert_eq!(services[0].package, "helloworld");
    }

    #[test]
    fn parse_methods() {
        let services = parse_proto_content(SAMPLE_PROTO);
        assert_eq!(services[0].methods.len(), 3);
        assert_eq!(services[0].methods[0].name, "SayHello");
        assert_eq!(services[0].methods[0].input_type, "HelloRequest");
    }

    #[test]
    fn parse_streaming_flags() {
        let services = parse_proto_content(SAMPLE_PROTO);
        let stream_method = &services[0].methods[2];
        assert_eq!(stream_method.name, "StreamGreet");
        assert!(stream_method.client_streaming);
        assert!(stream_method.server_streaming);
    }

    #[test]
    fn services_to_endpoints_grpc_path_format() {
        let services = parse_proto_content(SAMPLE_PROTO);
        let endpoints = services_to_endpoints("https://api.example.com", &services);
        assert_eq!(endpoints.len(), 3);
        assert_eq!(endpoints[0].path, "/helloworld.Greeter/SayHello");
        assert_eq!(endpoints[0].method, "POST");
    }

    #[test]
    fn parse_nonexistent_file_returns_error() {
        assert!(parse_proto("/nonexistent/path/file.proto").is_err());
    }
}
