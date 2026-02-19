use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use clap::Parser;
use crab_mitm::daemon::{
    default_socket_path, default_token_path_for_principal, ensure_daemon_started,
    read_token_from_file, send_rpc,
};
use serde_json::{Map, Value, json};

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
const TRAFFIC_BODY_PREVIEW_MAX_CHARS: usize = 2048;

#[derive(Debug, Parser)]
#[command(name = "crab-mcp", version, about = "Crab Proxy MCP stdio server")]
struct Cli {
    #[arg(long)]
    socket: Option<PathBuf>,

    #[arg(long)]
    daemon_path: Option<PathBuf>,

    #[arg(long, default_value = "mcp")]
    principal: String,

    #[arg(long)]
    token_path: Option<PathBuf>,

    #[arg(long, default_value_t = true)]
    ensure_daemon: bool,
}

struct DaemonBridge {
    socket_path: PathBuf,
    daemon_path: PathBuf,
    token_path: PathBuf,
    principal: String,
    ensure_daemon: bool,
    runtime: tokio::runtime::Runtime,
}

impl DaemonBridge {
    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        if self.ensure_daemon {
            ensure_daemon_started(&self.daemon_path, &self.socket_path).with_context(|| {
                format!("failed to ensure daemon at {}", self.daemon_path.display())
            })?;
        }
        let token = read_token_from_file(&self.token_path).with_context(|| {
            format!("failed to read token from {}", self.token_path.display())
        })?;

        self.runtime
            .block_on(send_rpc(
                &self.socket_path,
                &token,
                &self.principal,
                method,
                params,
            ))
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let socket_path = match cli.socket {
        Some(path) => path,
        None => default_socket_path().context("failed to resolve default socket path")?,
    };
    let token_path = match cli.token_path {
        Some(path) => path,
        None => default_token_path_for_principal(&cli.principal)
            .with_context(|| format!("failed to resolve token path for {}", cli.principal))?,
    };
    let daemon_path = match cli.daemon_path {
        Some(path) => path,
        None => default_daemon_path().context("failed to resolve daemon path")?,
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to initialize runtime")?;

    let mut bridge = DaemonBridge {
        socket_path,
        daemon_path,
        token_path,
        principal: cli.principal,
        ensure_daemon: cli.ensure_daemon,
        runtime,
    };

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());

    loop {
        let message = match read_framed_message(&mut reader) {
            Ok(Some(message)) => message,
            Ok(None) => break,
            Err(err) => {
                let response = rpc_error(Value::Null, -32700, format!("parse error: {err:#}"));
                let _ = write_framed_message(&mut writer, &response);
                break;
            }
        };

        if let Some(response) = handle_message(message, &mut bridge) {
            write_framed_message(&mut writer, &response).context("failed to write response")?;
        }
    }

    Ok(())
}

fn handle_message(message: Value, bridge: &mut DaemonBridge) -> Option<Value> {
    let obj = match message.as_object() {
        Some(obj) => obj,
        None => return Some(rpc_error(Value::Null, -32600, "invalid request: expected object")),
    };

    let method = match obj.get("method").and_then(Value::as_str) {
        Some(method) => method,
        None => {
            let id = obj.get("id").cloned().unwrap_or(Value::Null);
            return Some(rpc_error(id, -32600, "invalid request: method is required"));
        }
    };

    let id = obj.get("id").cloned();
    let params = obj.get("params").cloned().unwrap_or(Value::Null);

    let Some(id) = id else {
        // Notification
        return match method {
            "notifications/initialized" => None,
            _ => None,
        };
    };

    let response = match method {
        "initialize" => rpc_ok(id, initialize_result()),
        "ping" => rpc_ok(id, json!({})),
        "tools/list" => rpc_ok(id, json!({ "tools": tool_definitions() })),
        "tools/call" => match handle_tools_call(&params, bridge) {
            Ok(result) => rpc_ok(id, result),
            Err(err) => rpc_error(id, -32602, format!("invalid tools/call params: {err:#}")),
        },
        _ => rpc_error(id, -32601, format!("method not found: {method}")),
    };

    Some(response)
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {
                "listChanged": false
            }
        },
        "serverInfo": {
            "name": "crab-mcp",
            "version": env!("CARGO_PKG_VERSION")
        },
        "instructions": "Use Crab tools to inspect status/logs/traffic and manage proxy runtime, engine config, and map/allow/rewrite rules."
    })
}

fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "crab_ping",
            "description": "Ping Crab daemon and verify RPC connectivity.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_version",
            "description": "Get daemon engine/protocol version.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_proxy_status",
            "description": "Get proxy runtime status.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_proxy_start",
            "description": "Start proxy runtime.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_proxy_stop",
            "description": "Stop proxy runtime.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_daemon_doctor",
            "description": "Run daemon self-check and return diagnostic fields.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_engine_config_get",
            "description": "Read current daemon engine config.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_engine_set_listen_addr",
            "description": "Set listen address (requires stopped proxy).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "listen_addr": { "type": "string" }
                },
                "required": ["listen_addr"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_engine_set_inspect_enabled",
            "description": "Enable/disable body inspection (requires stopped proxy).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" }
                },
                "required": ["enabled"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_engine_set_throttle",
            "description": "Set throttle config (requires stopped proxy).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" },
                    "latency_ms": { "type": "integer", "minimum": 0 },
                    "downstream_bps": { "type": "integer", "minimum": 0 },
                    "upstream_bps": { "type": "integer", "minimum": 0 },
                    "only_selected_hosts": { "type": "boolean" },
                    "selected_hosts": {
                        "type": "array",
                        "items": { "type": "string" }
                    }
                },
                "required": [
                    "enabled",
                    "latency_ms",
                    "downstream_bps",
                    "upstream_bps",
                    "only_selected_hosts",
                    "selected_hosts"
                ],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_engine_set_client_allowlist",
            "description": "Set LAN client allowlist (requires stopped proxy).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" },
                    "ips": {
                        "type": "array",
                        "items": { "type": "string" }
                    }
                },
                "required": ["enabled", "ips"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_engine_set_transparent",
            "description": "Set transparent proxy mode (requires stopped proxy).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "enabled": { "type": "boolean" },
                    "listen_port": { "type": "integer", "minimum": 1, "maximum": 65535 }
                },
                "required": ["enabled", "listen_port"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_engine_load_ca",
            "description": "Load CA cert/key paths (requires stopped proxy).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "cert_path": { "type": "string" },
                    "key_path": { "type": "string" }
                },
                "required": ["cert_path", "key_path"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_logs_tail",
            "description": "Read recent logs from daemon ring buffer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "after_seq": { "type": "integer", "minimum": 0 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_traffic_tail",
            "description": "Read recent HTTP(S) traffic entries with response/request previews from structured logs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "after_seq": { "type": "integer", "minimum": 0 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 1000 },
                    "max_entries": { "type": "integer", "minimum": 1, "maximum": 500 },
                    "include_headers": { "type": "boolean" },
                    "include_body_sample_b64": { "type": "boolean" }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_traffic_get",
            "description": "Get one HTTP(S) traffic entry by request_id from recent structured logs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request_id": { "type": "string" },
                    "after_seq": { "type": "integer", "minimum": 0 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 2000 },
                    "include_headers": { "type": "boolean" },
                    "include_body_sample_b64": { "type": "boolean" }
                },
                "required": ["request_id"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_dump",
            "description": "Read current allow/map/rewrite rules.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_list_allow",
            "description": "Read allowlist rules only.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_list_map_local",
            "description": "Read map_local rules only.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_list_map_remote",
            "description": "Read map_remote rules only.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_list_status_rewrite",
            "description": "Read status_rewrite rules only.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_clear",
            "description": "Clear all rules (daemon must be stopped).",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_add_allow",
            "description": "Add allowlist rule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" }
                },
                "required": ["matcher"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_remove_allow",
            "description": "Remove allowlist rules by matcher.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" }
                },
                "required": ["matcher"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_add_map_local_text",
            "description": "Add Map Local (inline text) rule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" },
                    "text": { "type": "string" },
                    "status_code": { "type": "integer", "minimum": 100, "maximum": 599 },
                    "content_type": { "type": "string" }
                },
                "required": ["matcher", "text"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_add_map_local_file",
            "description": "Add Map Local (file path) rule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" },
                    "file_path": { "type": "string" },
                    "status_code": { "type": "integer", "minimum": 100, "maximum": 599 },
                    "content_type": { "type": "string" }
                },
                "required": ["matcher", "file_path"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_remove_map_local",
            "description": "Remove map_local rules by matcher (optionally source_kind/source_value).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" },
                    "source_kind": { "type": "string", "enum": ["file", "text"] },
                    "source_value": { "type": "string" }
                },
                "required": ["matcher"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_add_map_remote",
            "description": "Add Map Remote rule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" },
                    "destination": { "type": "string" }
                },
                "required": ["matcher", "destination"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_remove_map_remote",
            "description": "Remove map_remote rules by matcher (optionally destination).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" },
                    "destination": { "type": "string" }
                },
                "required": ["matcher"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_add_status_rewrite",
            "description": "Add response status rewrite rule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" },
                    "to_status_code": { "type": "integer", "minimum": 100, "maximum": 599 },
                    "from_status_code": { "type": "integer", "minimum": -1, "maximum": 599 }
                },
                "required": ["matcher", "to_status_code"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rules_remove_status_rewrite",
            "description": "Remove status_rewrite rules by matcher (optionally from/to filters).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "matcher": { "type": "string" },
                    "from_status_code": { "type": "integer", "minimum": -1, "maximum": 599 },
                    "to_status_code": { "type": "integer", "minimum": 100, "maximum": 599 }
                },
                "required": ["matcher"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "crab_rpc",
            "description": "Send a raw daemon RPC method call (advanced).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "method": { "type": "string" },
                    "params": { "type": "object" }
                },
                "required": ["method"],
                "additionalProperties": false
            }
        }),
    ]
}

fn handle_tools_call(params: &Value, bridge: &mut DaemonBridge) -> Result<Value> {
    let obj = params
        .as_object()
        .ok_or_else(|| anyhow!("params must be an object"))?;
    let tool_name = obj
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("name is required"))?;

    let arguments = match obj.get("arguments") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => bail!("arguments must be an object"),
    };

    let result = match call_tool(tool_name, &arguments, bridge) {
        Ok(value) => tool_success(value),
        Err(err) => tool_error(format!("{err:#}")),
    };

    Ok(result)
}

fn call_tool(tool_name: &str, args: &Map<String, Value>, bridge: &mut DaemonBridge) -> Result<Value> {
    match tool_name {
        "crab_ping" => bridge.call("system.ping", json!({})),
        "crab_version" => bridge.call("system.version", json!({})),
        "crab_proxy_status" => bridge.call("proxy.status", json!({})),
        "crab_proxy_start" => bridge.call("proxy.start", json!({})),
        "crab_proxy_stop" => bridge.call("proxy.stop", json!({})),
        "crab_daemon_doctor" => bridge.call("daemon.doctor", json!({})),
        "crab_engine_config_get" => bridge.call("engine.config_dump", json!({})),
        "crab_engine_set_listen_addr" => {
            ensure_allowed_keys(args, &["listen_addr"])?;
            let listen_addr = arg_str_required(args, "listen_addr")?;
            bridge.call(
                "engine.set_listen_addr",
                json!({
                    "listen_addr": listen_addr,
                }),
            )
        }
        "crab_engine_set_inspect_enabled" => {
            ensure_allowed_keys(args, &["enabled"])?;
            let enabled = arg_bool_required(args, "enabled")?;
            bridge.call(
                "engine.set_inspect_enabled",
                json!({
                    "enabled": enabled,
                }),
            )
        }
        "crab_engine_set_throttle" => {
            ensure_allowed_keys(
                args,
                &[
                    "enabled",
                    "latency_ms",
                    "downstream_bps",
                    "upstream_bps",
                    "only_selected_hosts",
                    "selected_hosts",
                ],
            )?;
            let enabled = arg_bool_required(args, "enabled")?;
            let latency_ms = arg_u64_required(args, "latency_ms")?;
            let downstream_bps = arg_u64_required(args, "downstream_bps")?;
            let upstream_bps = arg_u64_required(args, "upstream_bps")?;
            let only_selected_hosts = arg_bool_required(args, "only_selected_hosts")?;
            let selected_hosts = arg_string_vec_required(args, "selected_hosts")?;
            bridge.call(
                "engine.set_throttle",
                json!({
                    "enabled": enabled,
                    "latency_ms": latency_ms,
                    "downstream_bps": downstream_bps,
                    "upstream_bps": upstream_bps,
                    "only_selected_hosts": only_selected_hosts,
                    "selected_hosts": selected_hosts,
                }),
            )
        }
        "crab_engine_set_client_allowlist" => {
            ensure_allowed_keys(args, &["enabled", "ips"])?;
            let enabled = arg_bool_required(args, "enabled")?;
            let ips = arg_string_vec_required(args, "ips")?;
            bridge.call(
                "engine.set_client_allowlist",
                json!({
                    "enabled": enabled,
                    "ips": ips,
                }),
            )
        }
        "crab_engine_set_transparent" => {
            ensure_allowed_keys(args, &["enabled", "listen_port"])?;
            let enabled = arg_bool_required(args, "enabled")?;
            let listen_port = arg_u64_required(args, "listen_port")?;
            if listen_port == 0 || listen_port > 65535 {
                bail!("listen_port must be between 1 and 65535");
            }
            bridge.call(
                "engine.set_transparent",
                json!({
                    "enabled": enabled,
                    "listen_port": listen_port,
                }),
            )
        }
        "crab_engine_load_ca" => {
            ensure_allowed_keys(args, &["cert_path", "key_path"])?;
            let cert_path = arg_str_required(args, "cert_path")?;
            let key_path = arg_str_required(args, "key_path")?;
            bridge.call(
                "engine.load_ca",
                json!({
                    "cert_path": cert_path,
                    "key_path": key_path,
                }),
            )
        }
        "crab_logs_tail" => {
            ensure_allowed_keys(args, &["after_seq", "limit"])?;
            let after_seq = arg_u64(args, "after_seq")?.unwrap_or(0);
            let limit = arg_u64(args, "limit")?.unwrap_or(200).min(1000);
            bridge.call(
                "logs.tail",
                json!({
                    "after_seq": after_seq,
                    "limit": limit,
                }),
            )
        }
        "crab_traffic_tail" => {
            ensure_allowed_keys(
                args,
                &[
                    "after_seq",
                    "limit",
                    "max_entries",
                    "include_headers",
                    "include_body_sample_b64",
                ],
            )?;
            let after_seq = arg_u64(args, "after_seq")?.unwrap_or(0);
            let limit = arg_u64(args, "limit")?.unwrap_or(400).min(1000);
            let max_entries = arg_u64(args, "max_entries")?.unwrap_or(100).min(500) as usize;
            let include_headers = arg_bool(args, "include_headers")?.unwrap_or(true);
            let include_body_sample_b64 =
                arg_bool(args, "include_body_sample_b64")?.unwrap_or(false);
            traffic_tail(
                bridge,
                after_seq,
                limit,
                max_entries,
                include_headers,
                include_body_sample_b64,
            )
        }
        "crab_traffic_get" => {
            ensure_allowed_keys(
                args,
                &[
                    "request_id",
                    "after_seq",
                    "limit",
                    "include_headers",
                    "include_body_sample_b64",
                ],
            )?;
            let request_id = arg_str_required(args, "request_id")?;
            let after_seq = arg_u64(args, "after_seq")?.unwrap_or(0);
            let limit = arg_u64(args, "limit")?.unwrap_or(1000).min(2000);
            let include_headers = arg_bool(args, "include_headers")?.unwrap_or(true);
            let include_body_sample_b64 =
                arg_bool(args, "include_body_sample_b64")?.unwrap_or(false);
            traffic_get(
                bridge,
                &request_id,
                after_seq,
                limit,
                include_headers,
                include_body_sample_b64,
            )
        }
        "crab_rules_dump" => bridge.call("engine.rules_dump", json!({})),
        "crab_rules_list_allow" => rules_dump_field(bridge, "allowlist"),
        "crab_rules_list_map_local" => rules_dump_field(bridge, "map_local"),
        "crab_rules_list_map_remote" => rules_dump_field(bridge, "map_remote"),
        "crab_rules_list_status_rewrite" => rules_dump_field(bridge, "status_rewrite"),
        "crab_rules_clear" => bridge.call("engine.rules_clear", json!({})),
        "crab_rules_add_allow" => {
            ensure_allowed_keys(args, &["matcher"])?;
            let matcher = arg_str_required(args, "matcher")?;
            bridge.call("engine.rules_add_allow", json!({ "matcher": matcher }))
        }
        "crab_rules_remove_allow" => {
            ensure_allowed_keys(args, &["matcher"])?;
            let matcher = arg_str_required(args, "matcher")?;
            bridge.call("engine.rules_remove_allow", json!({ "matcher": matcher }))
        }
        "crab_rules_add_map_local_text" => {
            ensure_allowed_keys(args, &["matcher", "text", "status_code", "content_type"])?;
            let matcher = arg_str_required(args, "matcher")?;
            let text = arg_str_required(args, "text")?;
            let status_code = arg_u64(args, "status_code")?.unwrap_or(200);
            if !(100..=599).contains(&status_code) {
                bail!("status_code must be between 100 and 599");
            }
            let mut params = json!({
                "matcher": matcher,
                "text": text,
                "status_code": status_code,
            });
            if let Some(content_type) = arg_str(args, "content_type")? {
                params["content_type"] = Value::String(content_type);
            }
            bridge.call("engine.rules_add_map_local_text", params)
        }
        "crab_rules_add_map_local_file" => {
            ensure_allowed_keys(args, &["matcher", "file_path", "status_code", "content_type"])?;
            let matcher = arg_str_required(args, "matcher")?;
            let file_path = arg_str_required(args, "file_path")?;
            let status_code = arg_u64(args, "status_code")?.unwrap_or(200);
            if !(100..=599).contains(&status_code) {
                bail!("status_code must be between 100 and 599");
            }
            let mut params = json!({
                "matcher": matcher,
                "file_path": file_path,
                "status_code": status_code,
            });
            if let Some(content_type) = arg_str(args, "content_type")? {
                params["content_type"] = Value::String(content_type);
            }
            bridge.call("engine.rules_add_map_local_file", params)
        }
        "crab_rules_remove_map_local" => {
            ensure_allowed_keys(args, &["matcher", "source_kind", "source_value"])?;
            let matcher = arg_str_required(args, "matcher")?;
            let mut params = json!({
                "matcher": matcher,
            });
            if let Some(source_kind) = arg_str(args, "source_kind")? {
                if source_kind != "file" && source_kind != "text" {
                    bail!("source_kind must be 'file' or 'text'");
                }
                params["source_kind"] = Value::String(source_kind);
            }
            if let Some(source_value) = arg_str(args, "source_value")? {
                params["source_value"] = Value::String(source_value);
            }
            bridge.call("engine.rules_remove_map_local", params)
        }
        "crab_rules_add_map_remote" => {
            ensure_allowed_keys(args, &["matcher", "destination"])?;
            let matcher = arg_str_required(args, "matcher")?;
            let destination = arg_str_required(args, "destination")?;
            bridge.call(
                "engine.rules_add_map_remote",
                json!({
                    "matcher": matcher,
                    "destination": destination,
                }),
            )
        }
        "crab_rules_remove_map_remote" => {
            ensure_allowed_keys(args, &["matcher", "destination"])?;
            let matcher = arg_str_required(args, "matcher")?;
            let mut params = json!({
                "matcher": matcher,
            });
            if let Some(destination) = arg_str(args, "destination")? {
                params["destination"] = Value::String(destination);
            }
            bridge.call("engine.rules_remove_map_remote", params)
        }
        "crab_rules_add_status_rewrite" => {
            ensure_allowed_keys(args, &["matcher", "to_status_code", "from_status_code"])?;
            let matcher = arg_str_required(args, "matcher")?;
            let to_status_code = arg_u64(args, "to_status_code")?
                .ok_or_else(|| anyhow!("to_status_code is required"))?;
            if !(100..=599).contains(&to_status_code) {
                bail!("to_status_code must be between 100 and 599");
            }
            let from_status_code = arg_i64(args, "from_status_code")?.unwrap_or(-1);
            if !(from_status_code == -1 || (100..=599).contains(&from_status_code)) {
                bail!("from_status_code must be -1 or between 100 and 599");
            }
            bridge.call(
                "engine.rules_add_status_rewrite",
                json!({
                    "matcher": matcher,
                    "to_status_code": to_status_code,
                    "from_status_code": from_status_code,
                }),
            )
        }
        "crab_rules_remove_status_rewrite" => {
            ensure_allowed_keys(args, &["matcher", "from_status_code", "to_status_code"])?;
            let matcher = arg_str_required(args, "matcher")?;
            let mut params = json!({
                "matcher": matcher,
            });
            if let Some(from_status_code) = arg_i64(args, "from_status_code")? {
                if !(from_status_code == -1 || (100..=599).contains(&from_status_code)) {
                    bail!("from_status_code must be -1 or between 100 and 599");
                }
                params["from_status_code"] = Value::Number(from_status_code.into());
            }
            if let Some(to_status_code) = arg_u64(args, "to_status_code")? {
                if !(100..=599).contains(&to_status_code) {
                    bail!("to_status_code must be between 100 and 599");
                }
                params["to_status_code"] = Value::Number(to_status_code.into());
            }
            bridge.call("engine.rules_remove_status_rewrite", params)
        }
        "crab_rpc" => {
            ensure_allowed_keys(args, &["method", "params"])?;
            let method = arg_str_required(args, "method")?;
            let params = match args.get("params") {
                None | Some(Value::Null) => json!({}),
                Some(Value::Object(map)) => Value::Object(map.clone()),
                Some(_) => bail!("params must be an object"),
            };
            bridge.call(&method, params)
        }
        _ => bail!("unknown tool: {tool_name}"),
    }
}

fn rules_dump_field(bridge: &mut DaemonBridge, key: &str) -> Result<Value> {
    let dump = bridge.call("engine.rules_dump", json!({}))?;
    let object = dump
        .as_object()
        .ok_or_else(|| anyhow!("engine.rules_dump returned non-object result"))?;
    let value = object
        .get(key)
        .ok_or_else(|| anyhow!("engine.rules_dump missing key: {key}"))?;
    Ok(json!({
        key: value
    }))
}

#[derive(Debug, Default, Clone)]
struct TrafficAggregate {
    request_id: Option<String>,
    event: Option<String>,
    method: Option<String>,
    url: Option<String>,
    peer: Option<String>,
    status: Option<u16>,
    duration_ms: Option<f64>,
    response_size_bytes: Option<u64>,
    map_local: Option<String>,
    map_remote: Option<String>,
    map_remote_to: Option<String>,
    request_headers: Option<String>,
    response_headers: Option<String>,
    request_body_preview: Option<String>,
    request_body_bytes: Option<u64>,
    request_body_sample_b64: Option<String>,
    response_body_preview: Option<String>,
    response_body_bytes: Option<u64>,
    response_body_sample_b64: Option<String>,
    seq_first: u64,
    seq_last: u64,
    ts_unix_ms: u64,
}

impl TrafficAggregate {
    fn to_value(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "event": self.event,
            "method": self.method,
            "url": self.url,
            "peer": self.peer,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "response_size_bytes": self.response_size_bytes,
            "map_local": self.map_local,
            "map_remote": self.map_remote,
            "map_remote_to": self.map_remote_to,
            "request_headers": self.request_headers,
            "response_headers": self.response_headers,
            "request_body": {
                "bytes": self.request_body_bytes,
                "preview": self.request_body_preview,
                "sample_b64": self.request_body_sample_b64
            },
            "response_body": {
                "bytes": self.response_body_bytes,
                "preview": self.response_body_preview,
                "sample_b64": self.response_body_sample_b64
            },
            "seq_first": self.seq_first,
            "seq_last": self.seq_last,
            "ts_unix_ms": self.ts_unix_ms
        })
    }
}

fn traffic_tail(
    bridge: &mut DaemonBridge,
    after_seq: u64,
    limit: u64,
    max_entries: usize,
    include_headers: bool,
    include_body_sample_b64: bool,
) -> Result<Value> {
    let logs = bridge.call(
        "logs.tail",
        json!({
            "after_seq": after_seq,
            "limit": limit,
        }),
    )?;
    let (next_seq, records_scanned, mut entries) =
        aggregate_traffic_entries(&logs, include_headers, include_body_sample_b64)?;
    entries.sort_by(|left, right| right.seq_last.cmp(&left.seq_last));
    if entries.len() > max_entries {
        entries.truncate(max_entries);
    }

    Ok(json!({
        "next_seq": next_seq,
        "records_scanned": records_scanned,
        "entry_count": entries.len(),
        "entries": entries.iter().map(TrafficAggregate::to_value).collect::<Vec<_>>(),
    }))
}

fn traffic_get(
    bridge: &mut DaemonBridge,
    request_id: &str,
    after_seq: u64,
    limit: u64,
    include_headers: bool,
    include_body_sample_b64: bool,
) -> Result<Value> {
    let logs = bridge.call(
        "logs.tail",
        json!({
            "after_seq": after_seq,
            "limit": limit,
        }),
    )?;
    let (next_seq, records_scanned, mut entries) =
        aggregate_traffic_entries(&logs, include_headers, include_body_sample_b64)?;
    entries.sort_by(|left, right| right.seq_last.cmp(&left.seq_last));

    let Some(entry) = entries
        .into_iter()
        .find(|item| item.request_id.as_deref() == Some(request_id))
    else {
        bail!("request_id not found in current log window: {request_id}");
    };

    Ok(json!({
        "next_seq": next_seq,
        "records_scanned": records_scanned,
        "request_id": request_id,
        "entry": entry.to_value(),
    }))
}

fn aggregate_traffic_entries(
    logs: &Value,
    include_headers: bool,
    include_body_sample_b64: bool,
) -> Result<(u64, usize, Vec<TrafficAggregate>)> {
    let next_seq = value_to_u64(logs.get("next_seq").unwrap_or(&Value::Null)).unwrap_or(0);
    let records = logs
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("logs.tail response missing records array"))?;

    let mut by_key: HashMap<String, TrafficAggregate> = HashMap::new();
    let mut scanned = 0usize;

    for record in records {
        let Some(message) = record.get("message").and_then(Value::as_str) else {
            continue;
        };
        let Some(payload) = parse_structured_payload(message) else {
            continue;
        };

        scanned += 1;
        let seq = value_to_u64(record.get("seq").unwrap_or(&Value::Null)).unwrap_or(0);
        let ts_unix_ms =
            value_to_u64(record.get("ts_unix_ms").unwrap_or(&Value::Null)).unwrap_or(0);
        let payload_type = object_string_field(&payload, "type").unwrap_or_default();
        let event = object_string_field(&payload, "event").unwrap_or_default();
        let method = object_string_field(&payload, "method");
        let url = object_string_field(&payload, "url");
        let peer = object_string_field(&payload, "peer");
        let request_id = object_string_field(&payload, "request_id").filter(|value| !value.is_empty());

        let key = if let Some(id) = request_id.as_ref() {
            format!("id:{id}")
        } else if let (Some(m), Some(u), Some(p)) = (method.as_ref(), url.as_ref(), peer.as_ref()) {
            format!("fallback:{p}|{m}|{u}")
        } else {
            continue;
        };

        let entry = by_key.entry(key).or_insert_with(|| TrafficAggregate {
            seq_first: seq,
            seq_last: seq,
            ts_unix_ms,
            ..TrafficAggregate::default()
        });
        if seq > 0 && (entry.seq_first == 0 || seq < entry.seq_first) {
            entry.seq_first = seq;
        }
        if seq >= entry.seq_last {
            entry.seq_last = seq;
            entry.ts_unix_ms = ts_unix_ms;
        }

        if entry.request_id.is_none() {
            entry.request_id = request_id.clone();
        }
        if entry.method.is_none() {
            entry.method = method.clone();
        }
        if entry.url.is_none() {
            entry.url = url.clone();
        }
        if entry.peer.is_none() {
            entry.peer = peer.clone();
        }
        if !event.is_empty() {
            entry.event = Some(event.clone());
        }

        if payload_type == "entry" {
            if let Some(status) = object_u16_field(&payload, "status")
                .or_else(|| object_u16_field(&payload, "response_status"))
            {
                entry.status = Some(status);
            }
            if let Some(duration_ms) = object_f64_field(&payload, "duration_ms") {
                entry.duration_ms = Some(duration_ms);
            }
            if let Some(size) = object_u64_field(&payload, "response_size_bytes") {
                entry.response_size_bytes = Some(size);
            }
            if let Some(value) = object_string_field(&payload, "map_local") {
                entry.map_local = Some(value);
            }
            if let Some(value) = object_string_field(&payload, "map_remote") {
                entry.map_remote = Some(value);
            }
            if let Some(value) = object_string_field(&payload, "map_remote_to") {
                entry.map_remote_to = Some(value);
            }
            continue;
        }

        if payload_type != "meta" {
            continue;
        }

        match event.as_str() {
            "request_headers" => {
                if include_headers
                    && let Some(headers_b64) = object_string_field(&payload, "headers_b64")
                {
                    entry.request_headers = Some(
                        decode_base64_to_text(&headers_b64)
                            .unwrap_or_else(|| "<failed to decode headers_b64>".to_string()),
                    );
                }
            }
            "response_headers" => {
                if include_headers
                    && let Some(headers_b64) = object_string_field(&payload, "headers_b64")
                {
                    entry.response_headers = Some(
                        decode_base64_to_text(&headers_b64)
                            .unwrap_or_else(|| "<failed to decode headers_b64>".to_string()),
                    );
                }
                if let Some(status) = object_u16_field(&payload, "status")
                    .or_else(|| object_u16_field(&payload, "response_status"))
                {
                    entry.status = Some(status);
                }
            }
            "body_inspection" => {
                let direction = object_string_field(&payload, "direction").unwrap_or_default();
                let body_bytes = object_u64_field(&payload, "body_bytes");
                let response_status = object_u16_field(&payload, "response_status");
                let sample_b64 = object_string_field(&payload, "sample_b64");
                let preview = sample_b64.as_deref().and_then(decode_body_preview);

                if direction == "request" {
                    if let Some(bytes) = body_bytes {
                        entry.request_body_bytes = Some(bytes);
                    }
                    if let Some(text) = preview {
                        entry.request_body_preview = Some(text);
                    }
                    if include_body_sample_b64 {
                        entry.request_body_sample_b64 = sample_b64;
                    }
                } else if direction == "response" {
                    if let Some(bytes) = body_bytes {
                        entry.response_body_bytes = Some(bytes);
                        if entry.response_size_bytes.is_none() {
                            entry.response_size_bytes = Some(bytes);
                        }
                    }
                    if let Some(text) = preview {
                        entry.response_body_preview = Some(text);
                    }
                    if include_body_sample_b64 {
                        entry.response_body_sample_b64 = sample_b64;
                    }
                    if let Some(status) = response_status {
                        entry.status = Some(status);
                    }
                }
            }
            _ => {}
        }
    }

    Ok((next_seq, scanned, by_key.into_values().collect::<Vec<_>>()))
}

fn parse_structured_payload(line: &str) -> Option<Map<String, Value>> {
    let marker = line.find("CRAB_JSON ")?;
    let json_text = line[(marker + "CRAB_JSON ".len())..].trim();
    if json_text.is_empty() {
        return None;
    }

    let value: Value = serde_json::from_str(json_text).ok()?;
    value.as_object().cloned()
}

fn object_string_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    let value = object.get(key)?;
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(boolean) => Some(boolean.to_string()),
        _ => None,
    }
}

fn object_u64_field(object: &Map<String, Value>, key: &str) -> Option<u64> {
    let value = object.get(key)?;
    value_to_u64(value)
}

fn object_u16_field(object: &Map<String, Value>, key: &str) -> Option<u16> {
    let value = object.get(key)?;
    value_to_u64(value).and_then(|raw| u16::try_from(raw).ok())
}

fn object_f64_field(object: &Map<String, Value>, key: &str) -> Option<f64> {
    let value = object.get(key)?;
    value_to_f64(value)
}

fn value_to_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_i64().and_then(|signed| u64::try_from(signed).ok())),
        Value::String(text) => text.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn value_to_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn decode_base64_to_text(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some(String::new());
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(value).ok()?;
    Some(String::from_utf8_lossy(&bytes).to_string())
}

fn decode_body_preview(sample_b64: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(sample_b64)
        .ok()?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    Some(truncate_chars(&text, TRAFFIC_BODY_PREVIEW_MAX_CHARS))
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }

    let mut output = String::with_capacity(max_chars + 16);
    for (index, ch) in text.chars().enumerate() {
        if index >= max_chars {
            break;
        }
        output.push(ch);
    }
    output.push_str("...(truncated)");
    output
}

fn tool_success(payload: Value) -> Value {
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string());
    json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "structuredContent": payload
    })
}

fn tool_error(message: String) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": message
            }
        ],
        "isError": true
    })
}

fn ensure_allowed_keys(args: &Map<String, Value>, allowed_keys: &[&str]) -> Result<()> {
    let allowed = allowed_keys.iter().copied().collect::<HashSet<_>>();
    for key in args.keys() {
        if !allowed.contains(key.as_str()) {
            bail!("unknown argument: {key}");
        }
    }
    Ok(())
}

fn arg_str_required(args: &Map<String, Value>, key: &str) -> Result<String> {
    arg_str(args, key)?.ok_or_else(|| anyhow!("{key} is required"))
}

fn arg_str(args: &Map<String, Value>, key: &str) -> Result<Option<String>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => bail!("{key} must be a string"),
    }
}

fn arg_bool_required(args: &Map<String, Value>, key: &str) -> Result<bool> {
    arg_bool(args, key)?.ok_or_else(|| anyhow!("{key} is required"))
}

fn arg_bool(args: &Map<String, Value>, key: &str) -> Result<Option<bool>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => bail!("{key} must be a boolean"),
    }
}

fn arg_u64_required(args: &Map<String, Value>, key: &str) -> Result<u64> {
    arg_u64(args, key)?.ok_or_else(|| anyhow!("{key} is required"))
}

fn arg_string_vec_required(args: &Map<String, Value>, key: &str) -> Result<Vec<String>> {
    arg_string_vec(args, key)?.ok_or_else(|| anyhow!("{key} is required"))
}

fn arg_string_vec(args: &Map<String, Value>, key: &str) -> Result<Option<Vec<String>>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => {
            let mut result = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Value::String(text) => result.push(text.clone()),
                    _ => bail!("{key} must be an array of strings"),
                }
            }
            Ok(Some(result))
        }
        Some(_) => bail!("{key} must be an array of strings"),
    }
}

fn arg_u64(args: &Map<String, Value>, key: &str) -> Result<Option<u64>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| anyhow!("{key} must be an unsigned integer")),
        Some(_) => bail!("{key} must be an unsigned integer"),
    }
}

fn arg_i64(args: &Map<String, Value>, key: &str) -> Result<Option<i64>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| anyhow!("{key} must be an integer")),
        Some(_) => bail!("{key} must be an integer"),
    }
}

fn rpc_ok(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message.into()
        }
    })
}

fn read_framed_message<R: BufRead>(reader: &mut R) -> Result<Option<Value>> {
    let mut content_length: Option<usize> = None;
    let mut saw_header_line = false;

    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .context("failed to read frame header line")?;
        if read == 0 {
            if !saw_header_line {
                return Ok(None);
            }
            bail!("unexpected EOF while reading frame headers");
        }
        saw_header_line = true;

        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }

        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid frame header: {line}"))?;
        if name.eq_ignore_ascii_case("Content-Length") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .with_context(|| format!("invalid Content-Length: {}", value.trim()))?;
            content_length = Some(parsed);
        }
    }

    let length = content_length.ok_or_else(|| anyhow!("missing Content-Length header"))?;
    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .with_context(|| format!("failed to read frame payload ({length} bytes)"))?;

    let value: Value = serde_json::from_slice(&payload).context("failed to parse JSON payload")?;
    Ok(Some(value))
}

fn write_framed_message<W: Write>(writer: &mut W, message: &Value) -> Result<()> {
    let body = serde_json::to_vec(message).context("failed to serialize JSON response")?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())
        .context("failed to write frame header")?;
    writer
        .write_all(&body)
        .context("failed to write frame payload")?;
    writer.flush().context("failed to flush frame output")?;
    Ok(())
}

fn default_daemon_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("failed to resolve current executable path")?;
    let sibling = exe.with_file_name("crabd");
    if sibling.exists() {
        return Ok(sibling);
    }

    if let Some(dir) = exe.parent() {
        let candidate = dir.join("crabd");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Ok(Path::new("crabd").to_path_buf())
}
