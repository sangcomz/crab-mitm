use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use crab_mitm::daemon::{self, DaemonOptions};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "crabd", version, about = "Crab Proxy daemon")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start daemon server
    Serve {
        /// Override run directory (default: ~/Library/Application Support/CrabProxy/run)
        #[arg(long)]
        run_dir: Option<PathBuf>,

        /// Override socket path (default: <run_dir>/crabd.sock)
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    let (run_dir, socket_path) = match cli.command.unwrap_or(Command::Serve {
        run_dir: None,
        socket: None,
    }) {
        Command::Serve { run_dir, socket } => (run_dir, socket),
    };

    daemon::run_forever(DaemonOptions {
        socket_path,
        run_dir,
    })
    .await
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
