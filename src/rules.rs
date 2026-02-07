use std::path::PathBuf;

use http::StatusCode;

#[derive(Clone, Debug)]
pub enum MapSource {
    File(PathBuf),
    Text(String),
}

#[derive(Clone, Debug)]
pub struct MapLocalRule {
    pub matcher: Matcher,
    pub source: MapSource,
    pub status: StatusCode,
    pub content_type: Option<String>,
}

#[derive(Clone, Debug)]
pub struct StatusRewriteRule {
    pub matcher: Matcher,
    pub from: Option<StatusCode>,
    pub to: StatusCode,
}

#[derive(Clone, Debug, Default)]
pub struct Rules {
    pub allowlist: Vec<AllowRule>,
    pub map_local: Vec<MapLocalRule>,
    pub status_rewrite: Vec<StatusRewriteRule>,
}

#[derive(Clone, Debug)]
pub struct AllowRule {
    raw: String,
}

impl AllowRule {
    pub fn new(raw: impl Into<String>) -> Self {
        Self { raw: raw.into() }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn is_match(&self, scheme: &str, authority: &str, path_and_query: &str) -> bool {
        let raw = self.raw.trim();
        if raw.is_empty() {
            return false;
        }
        if raw == "*" || raw == "*.*" {
            return true;
        }

        let full = format!("{scheme}://{authority}{path_and_query}");
        if raw.starts_with("http://") || raw.starts_with("https://") {
            return full.starts_with(raw);
        }
        if raw.starts_with('/') {
            return path_and_query.starts_with(raw);
        }

        let host = extract_host(authority);
        let host_lc = host.to_ascii_lowercase();
        let raw_lc = raw.to_ascii_lowercase();

        if let Some(suffix) = raw_lc.strip_prefix("*.") {
            return host_lc.ends_with(&format!(".{suffix}"));
        }

        if raw_lc.contains('/') {
            let no_scheme = format!("{authority}{path_and_query}");
            return no_scheme
                .to_ascii_lowercase()
                .starts_with(&raw_lc);
        }

        host_lc == raw_lc || host_lc.ends_with(&format!(".{raw_lc}"))
    }
}

fn extract_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[')
        && let Some(close) = rest.find(']')
    {
        return &rest[..close];
    }
    authority.split(':').next().unwrap_or(authority)
}

#[derive(Clone, Debug)]
pub struct Matcher {
    raw: String,
}

impl Matcher {
    pub fn new(raw: impl Into<String>) -> Self {
        Self { raw: raw.into() }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn is_match(&self, scheme: &str, authority: &str, path_and_query: &str) -> bool {
        let full = format!("{scheme}://{authority}{path_and_query}");
        if self.raw.starts_with("http://") || self.raw.starts_with("https://") {
            return full.starts_with(&self.raw);
        }

        if self.raw.starts_with('/') {
            return path_and_query.starts_with(&self.raw);
        }

        let no_scheme = format!("{authority}{path_and_query}");
        no_scheme.starts_with(&self.raw)
    }
}

impl Rules {
    pub fn is_allowed(&self, scheme: &str, authority: &str, path_and_query: &str) -> bool {
        if self.allowlist.is_empty() {
            return true;
        }
        self.allowlist
            .iter()
            .any(|rule| rule.is_match(scheme, authority, path_and_query))
    }

    pub fn find_map_local(
        &self,
        scheme: &str,
        authority: &str,
        path_and_query: &str,
    ) -> Option<&MapLocalRule> {
        self.map_local
            .iter()
            .find(|rule| rule.matcher.is_match(scheme, authority, path_and_query))
    }

    pub fn rewrite_status(
        &self,
        scheme: &str,
        authority: &str,
        path_and_query: &str,
        current: StatusCode,
    ) -> Option<StatusCode> {
        for rule in &self.status_rewrite {
            if !rule.matcher.is_match(scheme, authority, path_and_query) {
                continue;
            }
            if let Some(from) = rule.from {
                if from != current {
                    continue;
                }
            }
            return Some(rule.to);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matcher_supports_full_url_prefix() {
        let m = Matcher::new("https://example.com/api");
        assert!(m.is_match("https", "example.com", "/api/v1"));
        assert!(!m.is_match("https", "example.com", "/health"));
    }

    #[test]
    fn matcher_supports_path_prefix() {
        let m = Matcher::new("/health");
        assert!(m.is_match("http", "example.com", "/healthz"));
        assert!(!m.is_match("http", "example.com", "/api"));
    }

    #[test]
    fn matcher_supports_authority_and_path_prefix() {
        let m = Matcher::new("example.com/api");
        assert!(m.is_match("http", "example.com", "/api/v1"));
        assert!(!m.is_match("http", "other.com", "/api/v1"));
    }

    #[test]
    fn rewrite_status_respects_optional_from() {
        let rules = Rules {
            allowlist: vec![],
            map_local: vec![],
            status_rewrite: vec![
                StatusRewriteRule {
                    matcher: Matcher::new("/api"),
                    from: Some(StatusCode::OK),
                    to: StatusCode::SERVICE_UNAVAILABLE,
                },
                StatusRewriteRule {
                    matcher: Matcher::new("/api"),
                    from: None,
                    to: StatusCode::IM_A_TEAPOT,
                },
            ],
        };

        let rewritten = rules.rewrite_status("http", "example.com", "/api", StatusCode::OK);
        assert_eq!(rewritten, Some(StatusCode::SERVICE_UNAVAILABLE));

        let rewritten = rules.rewrite_status("http", "example.com", "/api", StatusCode::CREATED);
        assert_eq!(rewritten, Some(StatusCode::IM_A_TEAPOT));
    }

    #[test]
    fn allow_rule_matches_all_with_wildcard() {
        let rule = AllowRule::new("*.*");
        assert!(rule.is_match("https", "example.com", "/a"));
    }

    #[test]
    fn allow_rule_matches_host_and_subdomains() {
        let rule = AllowRule::new("naver.com");
        assert!(rule.is_match("https", "naver.com", "/"));
        assert!(rule.is_match("https", "api.naver.com", "/"));
        assert!(!rule.is_match("https", "example.com", "/"));
    }

    #[test]
    fn rules_default_allows_everything_without_allowlist() {
        let rules = Rules::default();
        assert!(rules.is_allowed("https", "example.com", "/"));
    }
}
