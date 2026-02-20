use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use crab_mitm::daemon::{
    default_socket_path, default_token_path_for_principal, ensure_daemon_started,
    read_token_from_file, send_rpc,
};
use serde_json::{Value, json};

#[derive(Debug, Parser)]
#[command(name = "crabctl", version, about = "Crab Proxy daemon control CLI")]
struct Cli {
    #[arg(long)]
    socket: Option<PathBuf>,

    #[arg(long)]
    daemon_path: Option<PathBuf>,

    #[arg(long, default_value = "cli")]
    principal: String,

    #[arg(long)]
    token_path: Option<PathBuf>,

    #[arg(long, default_value_t = true)]
    ensure_daemon: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Send a raw RPC request
    Rpc(RpcArgs),

    /// Ping daemon
    Ping,

    /// Start proxy
    Start,

    /// Stop proxy
    Stop,

    /// Proxy status
    Status,

    /// Rotate token files and invalidate current sessions
    RotateToken,

    /// Read logs
    #[command(subcommand)]
    Logs(LogsCommand),
}

#[derive(Debug, Args)]
struct RpcArgs {
    #[arg(long)]
    method: String,

    #[arg(long, default_value = "{}")]
    params: String,

    #[arg(long, default_value_t = false)]
    compact: bool,
}

#[derive(Debug, Subcommand)]
enum LogsCommand {
    Tail {
        #[arg(long, default_value_t = 200)]
        limit: u64,

        #[arg(long, default_value_t = 0)]
        after_seq: u64,
    },
    Follow {
        #[arg(long, default_value_t = 200)]
        limit: u64,

        #[arg(long, default_value_t = 200)]
        interval_ms: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let socket_path = match cli.socket {
        Some(path) => path,
        None => default_socket_path()?,
    };

    if cli.ensure_daemon {
        let daemon_path = match cli.daemon_path {
            Some(path) => path,
            None => default_daemon_path().context("failed to resolve daemon path")?,
        };
        ensure_daemon_started(&daemon_path, &socket_path)?;
    }

    let token_path = match cli.token_path {
        Some(path) => path,
        None => default_token_path_for_principal(&cli.principal)?,
    };
    let token = read_token_from_file(&token_path)?;

    match cli.command {
        Command::Rpc(args) => {
            let params: Value = serde_json::from_str(&args.params)
                .with_context(|| format!("invalid params JSON: {}", args.params))?;
            let result =
                send_rpc(&socket_path, &token, &cli.principal, &args.method, params).await?;
            print_json(&result, args.compact)?;
        }
        Command::Ping => {
            let result = send_rpc(
                &socket_path,
                &token,
                &cli.principal,
                "system.ping",
                json!({}),
            )
            .await?;
            print_json(&result, false)?;
        }
        Command::Start => {
            let result = send_rpc(
                &socket_path,
                &token,
                &cli.principal,
                "proxy.start",
                json!({}),
            )
            .await?;
            print_json(&result, false)?;
        }
        Command::Stop => {
            let result = send_rpc(
                &socket_path,
                &token,
                &cli.principal,
                "proxy.stop",
                json!({}),
            )
            .await?;
            print_json(&result, false)?;
        }
        Command::Status => {
            let result = send_rpc(
                &socket_path,
                &token,
                &cli.principal,
                "proxy.status",
                json!({}),
            )
            .await?;
            print_json(&result, false)?;
        }
        Command::RotateToken => {
            let result = send_rpc(
                &socket_path,
                &token,
                &cli.principal,
                "system.rotate_token",
                json!({}),
            )
            .await?;
            print_json(&result, false)?;
        }
        Command::Logs(logs) => match logs {
            LogsCommand::Tail { limit, after_seq } => {
                let result = send_rpc(
                    &socket_path,
                    &token,
                    &cli.principal,
                    "logs.tail",
                    json!({"limit": limit, "after_seq": after_seq}),
                )
                .await?;
                print_logs_tail(&result)?;
            }
            LogsCommand::Follow { limit, interval_ms } => {
                let mut cursor = 0u64;
                loop {
                    let result = send_rpc(
                        &socket_path,
                        &token,
                        &cli.principal,
                        "logs.tail",
                        json!({"limit": limit, "after_seq": cursor}),
                    )
                    .await?;

                    if let Some(next) = result.get("next_seq").and_then(|v| v.as_u64()) {
                        cursor = next;
                    }
                    if let Some(records) = result.get("records").and_then(|v| v.as_array()) {
                        for record in records {
                            if let Some(message) = record.get("message").and_then(|v| v.as_str()) {
                                println!("{message}");
                            }
                        }
                    }

                    tokio::time::sleep(Duration::from_millis(interval_ms.max(10))).await;
                }
            }
        },
    }

    Ok(())
}

fn print_json(value: &Value, compact: bool) -> Result<()> {
    if compact {
        println!("{}", serde_json::to_string(value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

fn print_logs_tail(value: &Value) -> Result<()> {
    if let Some(records) = value.get("records").and_then(|v| v.as_array()) {
        for record in records {
            if let Some(message) = record.get("message").and_then(|v| v.as_str()) {
                println!("{message}");
            }
        }
        return Ok(());
    }

    print_json(value, false)
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
