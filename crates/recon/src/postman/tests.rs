use super::*;
use std::collections::HashMap;

#[test]
fn resolve_vars_postman_style() {
    let vars: HashMap<String, String> =
        [("base_url".to_string(), "https://api.example.com".to_string())].into();
    assert_eq!(
        resolve_vars("{{base_url}}/users", &vars),
        "https://api.example.com/users"
    );
}

#[test]
fn resolve_vars_insomnia_style() {
    let vars: HashMap<String, String> =
        [("base_url".to_string(), "https://api.example.com".to_string())].into();
    assert_eq!(
        resolve_vars("{{ base_url }}/users", &vars),
        "https://api.example.com/users"
    );
}

#[test]
fn extract_path_from_url_with_path() {
    assert_eq!(
        extract_path_from_url("https://api.example.com/v1/users"),
        "/v1/users"
    );
}

#[test]
fn extract_path_from_url_no_path() {
    assert_eq!(extract_path_from_url("https://api.example.com"), "/");
}

#[test]
fn parse_postman_minimal_collection() {
    let json = r#"{
        "info": { "_postman_schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
        "item": [
            {
                "name": "Get Users",
                "request": {
                    "method": "GET",
                    "url": { "raw": "https://api.example.com/users", "query": [] }
                }
            }
        ],
        "variable": []
    }"#;
    let tmp = std::env::temp_dir().join("nevelio_test_postman.json");
    std::fs::write(&tmp, json).unwrap();
    let eps = parse_postman(tmp.to_str().unwrap()).unwrap();
    assert_eq!(eps.len(), 1);
    assert_eq!(eps[0].method, "GET");
    assert_eq!(eps[0].path, "/users");
}

#[test]
fn parse_postman_resolves_variables() {
    let json = r#"{
        "info": { "_postman_schema": "..." },
        "item": [
            {
                "name": "Get Users",
                "request": {
                    "method": "GET",
                    "url": { "raw": "{{base_url}}/users", "query": [] }
                }
            }
        ],
        "variable": [
            { "key": "base_url", "value": "https://api.example.com" }
        ]
    }"#;
    let tmp = std::env::temp_dir().join("nevelio_test_postman_vars.json");
    std::fs::write(&tmp, json).unwrap();
    let eps = parse_postman(tmp.to_str().unwrap()).unwrap();
    assert_eq!(eps.len(), 1);
    assert_eq!(eps[0].full_url, "https://api.example.com/users");
}

#[test]
fn parse_postman_nested_folders() {
    let json = r#"{
        "info": { "_postman_schema": "..." },
        "item": [
            {
                "name": "Users",
                "item": [
                    {
                        "name": "List",
                        "request": { "method": "GET", "url": { "raw": "https://api.example.com/users", "query": [] } }
                    },
                    {
                        "name": "Create",
                        "request": { "method": "POST", "url": { "raw": "https://api.example.com/users", "query": [] } }
                    }
                ]
            }
        ],
        "variable": []
    }"#;
    let tmp = std::env::temp_dir().join("nevelio_test_postman_folders.json");
    std::fs::write(&tmp, json).unwrap();
    let eps = parse_postman(tmp.to_str().unwrap()).unwrap();
    assert_eq!(eps.len(), 2);
}

#[test]
fn test_parse_insomnia_export() {
    let json = r#"{
        "_type": "export",
        "__export_format": 4,
        "__export_date": "2024-01-01",
        "__export_source": "insomnia.desktop.app",
        "resources": [
            {
                "_type": "environment",
                "_id": "env_1",
                "data": { "base_url": "https://api.example.com" }
            },
            {
                "_type": "request",
                "_id": "req_1",
                "method": "GET",
                "url": "{{ base_url }}/products",
                "parameters": [{ "name": "page", "value": "1", "disabled": false }]
            }
        ]
    }"#;
    let tmp = std::env::temp_dir().join("nevelio_test_insomnia.json");
    std::fs::write(&tmp, json).unwrap();
    let eps = parse_postman(tmp.to_str().unwrap()).unwrap();
    assert_eq!(eps.len(), 1);
    assert_eq!(eps[0].method, "GET");
    assert_eq!(eps[0].path, "/products");
    assert_eq!(eps[0].parameters.len(), 1);
    assert_eq!(eps[0].parameters[0].name, "page");
}

#[test]
fn parse_postman_url_as_string() {
    let json = r#"{
        "info": { "_postman_schema": "..." },
        "item": [
            {
                "name": "Ping",
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/ping"
                }
            }
        ],
        "variable": []
    }"#;
    let tmp = std::env::temp_dir().join("nevelio_test_postman_str_url.json");
    std::fs::write(&tmp, json).unwrap();
    let eps = parse_postman(tmp.to_str().unwrap()).unwrap();
    assert_eq!(eps.len(), 1);
    assert_eq!(eps[0].path, "/ping");
}
