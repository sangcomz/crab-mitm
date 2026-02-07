use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use crab_mitm::{ca, config, proxy};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "crab-mitm",
    version,
    about = "MITM proxy for network debugging (HTTP/HTTPS)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy server
    Run(RunArgs),
    /// Generate a root CA (install/trust this cert on your device for HTTPS MITM)
    Ca(CaArgs),
}

#[derive(Args, Debug)]
struct RunArgs {
    /// Listen address, e.g. 127.0.0.1:8080
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,

    /// TOML config file for rules (map_local / status_rewrite)
    #[arg(long)]
    config: Option<PathBuf>,

    /// Root CA certificate PEM (required for HTTPS MITM)
    #[arg(long)]
    ca_cert: Option<PathBuf>,

    /// Root CA private key PEM (required for HTTPS MITM)
    #[arg(long)]
    ca_key: Option<PathBuf>,

    /// Map local response: MATCH=./path/to/file (repeatable; takes precedence over config file)
    #[arg(long, value_parser = config::parse_map_arg)]
    map: Vec<config::MapArg>,

    /// Rewrite status: MATCH=TO or MATCH=FROM:TO (repeatable; takes precedence over config file)
    #[arg(long, value_parser = config::parse_rewrite_arg)]
    rewrite_status: Vec<config::RewriteArg>,

    /// Enable request/response body inspection logs
    #[arg(long, default_value_t = false)]
    inspect_body: bool,

    /// Number of bytes sampled from each body for log preview
    #[arg(long, default_value_t = 16 * 1024)]
    inspect_sample_bytes: usize,

    /// Spool body bytes to files for later inspection (implies --inspect-body behavior)
    #[arg(long, default_value_t = false)]
    inspect_spool: bool,

    /// Directory to place spool files (default: system temp dir)
    #[arg(long)]
    inspect_spool_dir: Option<PathBuf>,

    /// Per-body spool file size cap in bytes
    #[arg(long, default_value_t = 100 * 1024 * 1024)]
    inspect_spool_max_bytes: u64,

    /// Increase log verbosity (-v, -vv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Args, Debug)]
struct CaArgs {
    /// Common name for the generated CA certificate
    #[arg(long, default_value = "Crab MITM CA")]
    common_name: String,

    /// Output certificate PEM path
    #[arg(long, default_value = "ca.crt.pem")]
    out_cert: PathBuf,

    /// Output private key PEM path
    #[arg(long, default_value = "ca.key.pem")]
    out_key: PathBuf,

    /// Validity in days
    #[arg(long, default_value_t = 3650)]
    days: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Ca(args) => {
            ca::generate_ca_to_files(&args.common_name, args.days, &args.out_cert, &args.out_key)
                .with_context(|| "failed to generate CA")?;
            println!("Wrote CA cert: {}", args.out_cert.display());
            println!("Wrote CA key : {}", args.out_key.display());
            println!();
            println!("Next:");
            println!("- Trust/install the CA cert on your device/browser");
            println!(
                "- Run: crab-mitm run --ca-cert {} --ca-key {}",
                args.out_cert.display(),
                args.out_key.display()
            );
            Ok(())
        }
        Command::Run(args) => {
            init_tracing(args.verbose)?;

            let rules = Arc::new(
                config::load_rules(args.config.as_deref(), &args.map, &args.rewrite_status)
                    .with_context(|| "failed to load rules")?,
            );
            let inspect = Arc::new(proxy::InspectConfig {
                enabled: args.inspect_body || args.inspect_spool,
                sample_bytes: args.inspect_sample_bytes,
                spool: args.inspect_spool,
                spool_dir: args.inspect_spool_dir.clone(),
                spool_max_bytes: args.inspect_spool_max_bytes,
            });

            let ca =
                match (&args.ca_cert, &args.ca_key) {
                    (Some(cert), Some(key)) => Some(Arc::new(
                        ca::CertificateAuthority::from_pem_files(cert, key)
                            .with_context(|| "failed to load CA (check --ca-cert/--ca-key)")?,
                    )),
                    (None, None) => {
                        let default_cert = PathBuf::from("ca.crt.pem");
                        let default_key = PathBuf::from("ca.key.pem");
                        if default_cert.exists() && default_key.exists() {
                            Some(Arc::new(
                                ca::CertificateAuthority::from_pem_files(
                                    &default_cert,
                                    &default_key,
                                )
                                .with_context(
                                    || "failed to load default CA (ca.crt.pem/ca.key.pem)",
                                )?,
                            ))
                        } else {
                            None
                        }
                    }
                    _ => anyhow::bail!("--ca-cert and --ca-key must be provided together"),
                };

            if ca.is_none() {
                tracing::warn!(
                    "no CA provided; HTTPS will be tunneled (no MITM), so map_local/status_rewrite won't apply to HTTPS"
                );
            }

            proxy::run(&args.listen, ca, rules, inspect).await
        }
    }
}

fn init_tracing(verbose: u8) -> Result<()> {
    let base = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(base));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    Ok(())
}
