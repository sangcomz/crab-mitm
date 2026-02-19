use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: u32 = 1;

pub const AUTH_FAILED: i32 = 1;
pub const INVALID_PARAMS: i32 = 2;
pub const STATE_ERROR: i32 = 3;
pub const IO_ERROR: i32 = 4;
pub const INTERNAL_ERROR: i32 = 5;
pub const PRINCIPAL_MISMATCH: i32 = 8;
pub const PERMISSION_DENIED: i32 = 9;
pub const SESSION_EXPIRED: i32 = 10;
pub const METHOD_NOT_FOUND: i32 = 11;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcResponse {
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeParams {
    pub protocol_version: u32,
    pub token: String,
    #[serde(default)]
    pub client_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResult {
    pub session_id: String,
    pub protocol_version: u32,
    pub principal: String,
    pub scopes: Vec<String>,
    pub principal_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
    pub seq: u64,
    pub level: u8,
    pub message: String,
    pub ts_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogsTailResult {
    pub next_seq: u64,
    pub records: Vec<LogRecord>,
}

pub type ParamsMap = HashMap<String, Value>;

pub fn parse_params_map(value: &Value) -> Result<ParamsMap, String> {
    match value {
        Value::Object(map) => Ok(map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<HashMap<_, _>>()),
        Value::Null => Ok(HashMap::new()),
        _ => Err("params must be a JSON object".to_string()),
    }
}

pub fn param_as_bool(params: &ParamsMap, key: &str) -> Result<Option<bool>, String> {
    match params.get(key) {
        None => Ok(None),
        Some(Value::Bool(v)) => Ok(Some(*v)),
        Some(_) => Err(format!("{key} must be a boolean")),
    }
}

pub fn param_as_u64(params: &ParamsMap, key: &str) -> Result<Option<u64>, String> {
    match params.get(key) {
        None => Ok(None),
        Some(Value::Number(v)) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{key} must be an unsigned integer")),
        Some(_) => Err(format!("{key} must be an unsigned integer")),
    }
}

pub fn param_as_i64(params: &ParamsMap, key: &str) -> Result<Option<i64>, String> {
    match params.get(key) {
        None => Ok(None),
        Some(Value::Number(v)) => v
            .as_i64()
            .map(Some)
            .ok_or_else(|| format!("{key} must be an integer")),
        Some(_) => Err(format!("{key} must be an integer")),
    }
}

pub fn param_as_str<'a>(params: &'a ParamsMap, key: &str) -> Result<Option<&'a str>, String> {
    match params.get(key) {
        None => Ok(None),
        Some(Value::String(v)) => Ok(Some(v.as_str())),
        Some(_) => Err(format!("{key} must be a string")),
    }
}

pub fn param_as_string_vec(params: &ParamsMap, key: &str) -> Result<Option<Vec<String>>, String> {
    match params.get(key) {
        None => Ok(None),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::String(v) => out.push(v.clone()),
                    _ => return Err(format!("{key} must be an array of strings")),
                }
            }
            Ok(Some(out))
        }
        Some(_) => Err(format!("{key} must be an array of strings")),
    }
}
