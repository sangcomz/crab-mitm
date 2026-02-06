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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use http::StatusCode;

    use super::*;
    use crate::rules::MapSource;

    #[test]
    fn parse_map_arg_validates_format() {
        let parsed = parse_map_arg("example.com/=./local.txt").expect("valid map arg");
        assert_eq!(parsed.matcher, "example.com/");
        assert_eq!(parsed.path, PathBuf::from("./local.txt"));

        assert!(parse_map_arg("=").is_err());
        assert!(parse_map_arg("example.com/=").is_err());
        assert!(parse_map_arg("=./local.txt").is_err());
    }

    #[test]
    fn parse_rewrite_arg_supports_two_forms() {
        let simple = parse_rewrite_arg("example.com/=418").expect("valid simple rewrite");
        assert_eq!(simple.matcher, "example.com/");
        assert_eq!(simple.from, None);
        assert_eq!(simple.to, 418);

        let conditional = parse_rewrite_arg("/api=200:503").expect("valid conditional rewrite");
        assert_eq!(conditional.matcher, "/api");
        assert_eq!(conditional.from, Some(200));
        assert_eq!(conditional.to, 503);

        assert!(parse_rewrite_arg("/api=abc").is_err());
        assert!(parse_rewrite_arg("/api=200:abc").is_err());
    }

    #[test]
    fn load_rules_reads_toml_and_applies_cli_first() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("crab-mitm-config-test-{now}"));
        fs::create_dir_all(&dir).expect("create temp dir");

        let local_path = dir.join("local.txt");
        fs::write(&local_path, "LOCAL").expect("write local file");

        let cfg_path = dir.join("rules.toml");
        fs::write(
            &cfg_path,
            format!(
                r#"
[[map_local]]
match = "example.com/"
file = "{}"
status = 201

[[status_rewrite]]
match = "example.com/"
to = 503
"#,
                local_path.display()
            ),
        )
        .expect("write config");

        let cli_rewrite = RewriteArg {
            matcher: "example.com/".to_string(),
            from: None,
            to: 418,
        };
        let rules = load_rules(Some(&cfg_path), &[], &[cli_rewrite]).expect("load rules");

        assert_eq!(rules.map_local.len(), 1);
        match &rules.map_local[0].source {
            MapSource::File(path) => assert_eq!(path, &local_path),
            _ => panic!("expected map_local file source"),
        }
        assert_eq!(rules.map_local[0].status, StatusCode::CREATED);

        let rewritten = rules.rewrite_status("http", "example.com", "/", StatusCode::OK);
        assert_eq!(rewritten, Some(StatusCode::IM_A_TEAPOT));

        let _ = fs::remove_file(cfg_path);
        let _ = fs::remove_file(local_path);
        let _ = fs::remove_dir_all(dir);
    }
}
