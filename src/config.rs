use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use http::StatusCode;
use serde::Deserialize;

use crate::rules::{MapLocalRule, MapSource, Matcher, Rules, StatusRewriteRule};

#[derive(Clone, Debug)]
pub struct MapArg {
    pub matcher: String,
    pub path: PathBuf,
}

pub fn parse_map_arg(input: &str) -> std::result::Result<MapArg, String> {
    let (matcher, path) = split_kv(input).ok_or_else(|| "expected MATCH=PATH".to_string())?;
    if matcher.trim().is_empty() {
        return Err("MATCH must not be empty".to_string());
    }
    if path.trim().is_empty() {
        return Err("PATH must not be empty".to_string());
    }
    Ok(MapArg {
        matcher: matcher.to_string(),
        path: PathBuf::from(path),
    })
}

#[derive(Clone, Debug)]
pub struct RewriteArg {
    pub matcher: String,
    pub from: Option<u16>,
    pub to: u16,
}

pub fn parse_rewrite_arg(input: &str) -> std::result::Result<RewriteArg, String> {
    let (matcher, rhs) =
        split_kv(input).ok_or_else(|| "expected MATCH=TO or MATCH=FROM:TO".to_string())?;
    if matcher.trim().is_empty() {
        return Err("MATCH must not be empty".to_string());
    }
    let (from, to) = if let Some((a, b)) = rhs.split_once(':') {
        let from = a
            .trim()
            .parse::<u16>()
            .map_err(|_| "FROM must be a valid status code (u16)".to_string())?;
        let to = b
            .trim()
            .parse::<u16>()
            .map_err(|_| "TO must be a valid status code (u16)".to_string())?;
        (Some(from), to)
    } else {
        let to = rhs
            .trim()
            .parse::<u16>()
            .map_err(|_| "TO must be a valid status code (u16)".to_string())?;
        (None, to)
    };

    if let Some(from) = from {
        StatusCode::from_u16(from)
            .map_err(|_| "FROM is not a valid HTTP status code".to_string())?;
    }
    StatusCode::from_u16(to).map_err(|_| "TO is not a valid HTTP status code".to_string())?;

    Ok(RewriteArg {
        matcher: matcher.to_string(),
        from,
        to,
    })
}

pub fn load_rules(
    config_path: Option<&Path>,
    cli_maps: &[MapArg],
    cli_rewrites: &[RewriteArg],
) -> Result<Rules> {
    let mut rules = Rules::default();

    for m in cli_maps {
        rules.map_local.push(MapLocalRule {
            matcher: Matcher::new(m.matcher.clone()),
            source: MapSource::File(m.path.clone()),
            status: StatusCode::OK,
            content_type: None,
        });
    }
    for r in cli_rewrites {
        rules.status_rewrite.push(StatusRewriteRule {
            matcher: Matcher::new(r.matcher.clone()),
            from: r
                .from
                .map(|c| StatusCode::from_u16(c).expect("validated by clap parser")),
            to: StatusCode::from_u16(r.to).expect("validated by clap parser"),
        });
    }

    if let Some(path) = config_path {
        let cfg_str = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let file_cfg: FileConfig = toml::from_str(&cfg_str)
            .with_context(|| format!("failed to parse TOML: {}", path.display()))?;
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));

        for m in file_cfg.map_local {
            let source = match (m.file, m.text) {
                (Some(f), None) => MapSource::File(resolve_path(base_dir, &f)),
                (None, Some(t)) => MapSource::Text(t),
                (None, None) => anyhow::bail!(
                    "map_local rule '{}' must set either 'file' or 'text'",
                    m.match_
                ),
                (Some(_), Some(_)) => anyhow::bail!(
                    "map_local rule '{}' must not set both 'file' and 'text'",
                    m.match_
                ),
            };
            let status = match m.status {
                Some(code) => StatusCode::from_u16(code).with_context(|| {
                    format!("invalid status code in map_local '{}': {}", m.match_, code)
                })?,
                None => StatusCode::OK,
            };
            rules.map_local.push(MapLocalRule {
                matcher: Matcher::new(m.match_),
                source,
                status,
                content_type: m.content_type,
            });
        }

        for r in file_cfg.status_rewrite {
            let from = match r.from {
                Some(code) => Some(StatusCode::from_u16(code).with_context(|| {
                    format!(
                        "invalid 'from' status in status_rewrite '{}': {}",
                        r.match_, code
                    )
                })?),
                None => None,
            };
            let to = StatusCode::from_u16(r.to).with_context(|| {
                format!(
                    "invalid 'to' status in status_rewrite '{}': {}",
                    r.match_, r.to
                )
            })?;
            rules.status_rewrite.push(StatusRewriteRule {
                matcher: Matcher::new(r.match_),
                from,
                to,
            });
        }
    }

    Ok(rules)
}

fn split_kv(input: &str) -> Option<(&str, &str)> {
    let mut it = input.splitn(2, '=');
    let k = it.next()?;
    let v = it.next()?;
    Some((k, v))
}

fn resolve_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    #[serde(default)]
    map_local: Vec<MapLocalConfig>,
    #[serde(default)]
    status_rewrite: Vec<StatusRewriteConfig>,
}

#[derive(Debug, Deserialize)]
struct MapLocalConfig {
    #[serde(rename = "match")]
    match_: String,
    file: Option<PathBuf>,
    text: Option<String>,
    status: Option<u16>,
    content_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StatusRewriteConfig {
    #[serde(rename = "match")]
    match_: String,
    from: Option<u16>,
    to: u16,
}
