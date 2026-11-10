//! Configuration, read once at startup from environment variables.

use crate::auth::Auth;
use crate::naming::{DEFAULT_TEMPLATE, Template};
use crate::storage::CHUNK_GRANULARITY;
use axum::http::{HeaderName, Method};

pub const DEFAULT_MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
pub const DEFAULT_UPLOAD_CHUNK_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_REDACT_HEADERS: &str = "authorization,proxy-authorization,cookie";

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub bucket: String,
    pub template: Template,
    /// Normalised to have no trailing slash; empty means "every path".
    pub path_prefix: String,
    pub methods: Vec<Method>,
    pub max_body_bytes: usize,
    /// Bodies larger than this are streamed to GCS in chunks of this size;
    /// smaller ones are buffered and written in one request.
    pub upload_chunk_bytes: usize,
    pub auth: Auth,
    /// Headers whose values are replaced with `[REDACTED]` in metadata.
    pub redact_headers: Vec<HeaderName>,
    pub emulator_host: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(&|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, String> {
        // Treat empty values as unset: Cloud Run and Terraform make it easy to
        // end up with `FOO=""`.
        let get = |k: &str| get(k).filter(|v| !v.is_empty());

        let port = match get("PORT") {
            None => 8080,
            Some(p) => p
                .parse()
                .map_err(|_| format!("PORT must be a port number, got {p:?}"))?,
        };

        let bucket = get("GCS_BUCKET").ok_or("GCS_BUCKET is required")?;
        let bucket = bucket
            .strip_prefix("gs://")
            .unwrap_or(&bucket)
            .trim_end_matches('/')
            .to_string();

        let template =
            Template::parse(&get("OBJECT_PATH_TEMPLATE").unwrap_or(DEFAULT_TEMPLATE.into()))?;

        let path_prefix = get("WEBHOOK_PATH_PREFIX").unwrap_or("/".into());
        if !path_prefix.starts_with('/') {
            return Err(format!(
                "WEBHOOK_PATH_PREFIX must start with '/', got {path_prefix:?}"
            ));
        }
        let path_prefix = path_prefix.trim_end_matches('/').to_string();

        let methods = get("ALLOWED_METHODS")
            .unwrap_or("POST".into())
            .split(',')
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(|m| {
                Method::from_bytes(m.to_ascii_uppercase().as_bytes())
                    .map_err(|_| format!("ALLOWED_METHODS contains invalid method {m:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if methods.is_empty() {
            return Err("ALLOWED_METHODS must list at least one method".into());
        }

        let max_body_bytes = match get("MAX_BODY_BYTES") {
            None => DEFAULT_MAX_BODY_BYTES,
            Some(s) => s
                .parse()
                .map_err(|_| format!("MAX_BODY_BYTES must be an integer, got {s:?}"))?,
        };

        let upload_chunk_bytes = match get("UPLOAD_CHUNK_BYTES") {
            None => DEFAULT_UPLOAD_CHUNK_BYTES,
            Some(s) => s
                .parse()
                .ok()
                .filter(|n: &usize| *n > 0 && n.is_multiple_of(CHUNK_GRANULARITY))
                .ok_or_else(|| {
                    format!(
                        "UPLOAD_CHUNK_BYTES must be a positive multiple of {CHUNK_GRANULARITY} \
                         (256 KiB), got {s:?}"
                    )
                })?,
        };

        let auth = Auth::from_env(&get)?;

        let mut redact_headers = get("REDACT_HEADERS")
            .unwrap_or(DEFAULT_REDACT_HEADERS.into())
            .split(',')
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(|h| {
                HeaderName::try_from(h)
                    .map_err(|_| format!("REDACT_HEADERS contains invalid header {h:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        // A shared secret sent in a header must never end up in the bucket.
        if let Some(h) = auth.secret_header()
            && !redact_headers.contains(h)
        {
            redact_headers.push(h.clone());
        }

        Ok(Self {
            port,
            bucket,
            template,
            path_prefix,
            methods,
            max_body_bytes,
            upload_chunk_bytes,
            auth,
            redact_headers,
            emulator_host: get("STORAGE_EMULATOR_HOST"),
        })
    }

    /// Whether `path` is under `WEBHOOK_PATH_PREFIX`.
    pub fn path_matches(&self, path: &str) -> bool {
        self.path_prefix.is_empty()
            || path == self.path_prefix
            || path
                .strip_prefix(&self.path_prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(pairs: &[(&str, &str)]) -> Result<Config, String> {
        let mut map: HashMap<String, String> = [("GCS_BUCKET", "b"), ("AUTH_MODE", "none")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        for (k, v) in pairs {
            map.insert(k.to_string(), v.to_string());
        }
        Config::from_lookup(&move |k| map.get(k).cloned())
    }

    #[test]
    fn defaults() {
        let c = config(&[]).unwrap();
        assert_eq!(c.port, 8080);
        assert_eq!(c.bucket, "b");
        assert_eq!(c.path_prefix, "");
        assert_eq!(c.methods, vec![Method::POST]);
        assert_eq!(c.max_body_bytes, 10 * 1024 * 1024);
        assert_eq!(c.upload_chunk_bytes, 8 * 1024 * 1024);
        assert_eq!(c.redact_headers.len(), 3);
        assert!(c.emulator_host.is_none());
    }

    #[test]
    fn bucket_and_auth_are_required() {
        assert!(
            Config::from_lookup(&|k| (k == "AUTH_MODE").then(|| "none".into()))
                .unwrap_err()
                .contains("GCS_BUCKET")
        );
        assert!(
            Config::from_lookup(&|k| (k == "GCS_BUCKET").then(|| "b".into()))
                .unwrap_err()
                .contains("AUTH_MODE")
        );
    }

    #[test]
    fn bucket_accepts_gs_url() {
        assert_eq!(
            config(&[("GCS_BUCKET", "gs://my-bucket/")]).unwrap().bucket,
            "my-bucket"
        );
    }

    #[test]
    fn empty_values_are_unset() {
        let c = config(&[("PORT", ""), ("OBJECT_PATH_TEMPLATE", "")]).unwrap();
        assert_eq!(c.port, 8080);
    }

    #[test]
    fn methods_are_parsed() {
        let c = config(&[("ALLOWED_METHODS", "post, put")]).unwrap();
        assert_eq!(c.methods, vec![Method::POST, Method::PUT]);
        assert!(config(&[("ALLOWED_METHODS", " , ")]).is_err());
    }

    #[test]
    fn invalid_values_are_rejected() {
        assert!(config(&[("PORT", "http")]).is_err());
        assert!(config(&[("MAX_BODY_BYTES", "10MB")]).is_err());
        assert!(config(&[("UPLOAD_CHUNK_BYTES", "1000000")]).is_err());
        assert!(config(&[("UPLOAD_CHUNK_BYTES", "0")]).is_err());
        assert!(config(&[("UPLOAD_CHUNK_BYTES", "524288")]).is_ok());
        assert!(config(&[("WEBHOOK_PATH_PREFIX", "webhooks")]).is_err());
        assert!(config(&[("OBJECT_PATH_TEMPLATE", "{path}")]).is_err());
        assert!(config(&[("REDACT_HEADERS", "bad header")]).is_err());
    }

    #[test]
    fn secret_header_is_always_redacted() {
        let c = config(&[
            ("AUTH_MODE", "header"),
            ("AUTH_HEADER", "X-Secret"),
            ("AUTH_SECRET", "s"),
            ("REDACT_HEADERS", "cookie"),
        ])
        .unwrap();
        let names: Vec<_> = c.redact_headers.iter().map(|h| h.as_str()).collect();
        assert_eq!(names, vec!["cookie", "x-secret"]);
    }

    #[test]
    fn path_prefix_matching() {
        let all = config(&[]).unwrap();
        assert!(all.path_matches("/"));
        assert!(all.path_matches("/anything/at/all"));

        let c = config(&[("WEBHOOK_PATH_PREFIX", "/webhook_acme/")]).unwrap();
        assert!(c.path_matches("/webhook_acme"));
        assert!(c.path_matches("/webhook_acme/"));
        assert!(c.path_matches("/webhook_acme/orders"));
        assert!(!c.path_matches("/webhook_acmeX"));
        assert!(!c.path_matches("/other"));
        assert!(!c.path_matches("/"));
    }
}
