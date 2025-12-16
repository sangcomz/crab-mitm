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
    pub map_local: Vec<MapLocalRule>,
    pub status_rewrite: Vec<StatusRewriteRule>,
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
