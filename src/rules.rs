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
    matcher: Matcher,
}

impl AllowRule {
    pub fn new(raw: impl Into<String>) -> Self {
        let raw = raw.into();
        Self {
            matcher: Matcher::new(raw.clone()),
            raw,
        }
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

        if is_full_url_pattern(raw) || raw.starts_with('/') {
            return self.matcher.is_match(scheme, authority, path_and_query);
        }

        let host = extract_host(authority);
        let host_lc = host.to_ascii_lowercase();
        let raw_lc = raw.to_ascii_lowercase();

        if let Some(suffix) = raw_lc.strip_prefix("*.") {
            return host_lc.len() > suffix.len()
                && host_lc.ends_with(suffix)
                && host_lc.as_bytes()[host_lc.len() - suffix.len() - 1] == b'.';
        }

        if raw_lc.contains('/') {
            return starts_with_authority_and_path_ignore_ascii_case(
                authority,
                path_and_query,
                raw,
            );
        }

        host_lc == raw_lc
            || (host_lc.len() > raw_lc.len()
                && host_lc.ends_with(&raw_lc)
                && host_lc.as_bytes()[host_lc.len() - raw_lc.len() - 1] == b'.')
    }

    pub fn is_ssl_proxy_match(&self, scheme: &str, authority: &str) -> bool {
        let raw = self.raw.trim();
        if raw.is_empty() {
            return false;
        }
        if raw == "*" || raw == "*.*" {
            return true;
        }

        let authority_pattern = if is_full_url_pattern(raw) {
            let Some((raw_scheme, remainder)) = raw.split_once("://") else {
                return false;
            };
            if !scheme.eq_ignore_ascii_case(raw_scheme) {
                return false;
            }
            remainder.split('/').next().unwrap_or("")
        } else {
            if raw.starts_with('/') {
                return false;
            }
            raw.split('/').next().unwrap_or(raw)
        };

        if authority_pattern.is_empty() {
            return false;
        }

        matches_authority_pattern(authority, authority_pattern)
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

fn split_host_port(value: &str) -> (&str, Option<&str>) {
    if let Some(rest) = value.strip_prefix('[')
        && let Some(close) = rest.find(']')
    {
        let host = &rest[..close];
        let remainder = &rest[close + 1..];
        if let Some(port) = remainder.strip_prefix(':')
            && !port.is_empty()
        {
            return (host, Some(port));
        }
        return (host, None);
    }

    if let Some((host, port)) = value.rsplit_once(':')
        && !host.is_empty()
        && !port.is_empty()
        && port.as_bytes().iter().all(|byte| byte.is_ascii_digit())
    {
        return (host, Some(port));
    }

    (value, None)
}

fn matches_authority_pattern(authority: &str, pattern: &str) -> bool {
    let (pattern_host, pattern_port) = split_host_port(pattern);
    if pattern_host.is_empty() {
        return false;
    }

    let (authority_host, authority_port) = split_host_port(authority);
    if let Some(pattern_port) = pattern_port
        && authority_port != Some(pattern_port)
    {
        return false;
    }

    let authority_host_lc = authority_host.to_ascii_lowercase();
    let pattern_host_lc = pattern_host.to_ascii_lowercase();

    if let Some(suffix) = pattern_host_lc.strip_prefix("*.") {
        return authority_host_lc.len() > suffix.len()
            && authority_host_lc.ends_with(suffix)
            && authority_host_lc.as_bytes()[authority_host_lc.len() - suffix.len() - 1] == b'.';
    }

    authority_host_lc == pattern_host_lc
        || (authority_host_lc.len() > pattern_host_lc.len()
            && authority_host_lc.ends_with(&pattern_host_lc)
            && authority_host_lc.as_bytes()[authority_host_lc.len() - pattern_host_lc.len() - 1]
                == b'.')
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
        let raw = self.raw.trim();
        if raw.is_empty() {
            return false;
        }
        if is_full_url_pattern(raw) {
            return starts_with_full_url(scheme, authority, path_and_query, raw);
        }

        if raw.starts_with('/') {
            return path_and_query.starts_with(raw);
        }

        starts_with_authority_and_path(authority, path_and_query, raw)
    }
}

fn is_full_url_pattern(raw: &str) -> bool {
    raw.starts_with("http://") || raw.starts_with("https://")
}

fn starts_with_full_url(scheme: &str, authority: &str, path_and_query: &str, raw: &str) -> bool {
    let Some((raw_scheme, remainder)) = raw.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case(raw_scheme) {
        return false;
    }
    starts_with_authority_and_path(authority, path_and_query, remainder)
}

fn starts_with_authority_and_path(authority: &str, path_and_query: &str, prefix: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    if prefix.len() <= authority.len() {
        return authority.as_bytes().starts_with(prefix.as_bytes());
    }
    if !prefix.as_bytes().starts_with(authority.as_bytes()) {
        return false;
    }
    path_and_query.starts_with(&prefix[authority.len()..])
}

fn starts_with_authority_and_path_ignore_ascii_case(
    authority: &str,
    path_and_query: &str,
    prefix: &str,
) -> bool {
    if prefix.is_empty() {
        return true;
    }
    if prefix.len() <= authority.len() {
        return authority
            .get(..prefix.len())
            .is_some_and(|left| left.eq_ignore_ascii_case(prefix));
    }
    if !prefix
        .get(..authority.len())
        .is_some_and(|left| left.eq_ignore_ascii_case(authority))
    {
        return false;
    }
    path_and_query
        .get(..prefix.len() - authority.len())
        .is_some_and(|left| left.eq_ignore_ascii_case(&prefix[authority.len()..]))
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

    pub fn is_mitm_allowed(&self, scheme: &str, authority: &str) -> bool {
        if self.allowlist.is_empty() {
            return false;
        }
        self.allowlist
            .iter()
            .any(|rule| rule.is_ssl_proxy_match(scheme, authority))
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

    #[test]
    fn allow_rule_ssl_proxy_match_uses_authority_only() {
        let rule = AllowRule::new("https://example.com/api/v1");
        assert!(rule.is_ssl_proxy_match("https", "example.com:443"));
        assert!(!rule.is_ssl_proxy_match("http", "example.com:80"));
    }

    #[test]
    fn allow_rule_ssl_proxy_match_supports_port_pattern() {
        let rule = AllowRule::new("example.com:8443");
        assert!(rule.is_ssl_proxy_match("https", "example.com:8443"));
        assert!(!rule.is_ssl_proxy_match("https", "example.com:443"));
    }

    #[test]
    fn allow_rule_ssl_proxy_match_rejects_path_only_pattern() {
        let rule = AllowRule::new("/graphql");
        assert!(!rule.is_ssl_proxy_match("https", "example.com:443"));
    }

    #[test]
    fn rules_default_disallows_mitm_without_allowlist() {
        let rules = Rules::default();
        assert!(!rules.is_mitm_allowed("https", "example.com:443"));
    }
}
