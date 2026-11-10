//! Object naming: turns a request path and receive time into GCS object names.

use chrono::{DateTime, Utc};

pub const DEFAULT_TEMPLATE: &str = "{path}/dt={date}/{timestamp}_{id}";

/// Suffix of the metadata object written next to each body.
pub const METADATA_SUFFIX: &str = ".meta.json";

/// GCS limits object names to 1024 bytes of UTF-8.
const MAX_OBJECT_NAME_LEN: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Token {
    Path,
    Id,
    Timestamp,
    UnixNanos,
    Date,
    Year,
    Month,
    Day,
    Hour,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Literal(String),
    Token(Token),
}

/// A parsed `OBJECT_PATH_TEMPLATE`.
#[derive(Debug, Clone)]
pub struct Template(Vec<Part>);

impl Template {
    pub fn parse(template: &str) -> Result<Self, String> {
        let mut parts = Vec::new();
        let mut rest = template;
        while let Some(start) = rest.find('{') {
            if start > 0 {
                parts.push(Part::Literal(rest[..start].to_string()));
            }
            let end = rest[start..]
                .find('}')
                .ok_or("OBJECT_PATH_TEMPLATE has an unclosed '{'")?
                + start;
            let token = match &rest[start + 1..end] {
                "path" => Token::Path,
                "id" => Token::Id,
                "timestamp" => Token::Timestamp,
                "unix_nanos" => Token::UnixNanos,
                "date" => Token::Date,
                "year" => Token::Year,
                "month" => Token::Month,
                "day" => Token::Day,
                "hour" => Token::Hour,
                other => {
                    return Err(format!(
                        "OBJECT_PATH_TEMPLATE has unknown placeholder {{{other}}}; expected one \
                         of {{path}} {{id}} {{timestamp}} {{unix_nanos}} {{date}} {{year}} \
                         {{month}} {{day}} {{hour}}"
                    ));
                }
            };
            parts.push(Part::Token(token));
            rest = &rest[end + 1..];
        }
        if !rest.is_empty() {
            parts.push(Part::Literal(rest.to_string()));
        }
        if !parts.contains(&Part::Token(Token::Id)) {
            return Err("OBJECT_PATH_TEMPLATE must contain {id} so object names are unique".into());
        }
        if template.ends_with('/') {
            return Err("OBJECT_PATH_TEMPLATE must not end with '/'".into());
        }
        Ok(Self(parts))
    }

    /// Render the base object name (without extension) for one request.
    pub fn render(&self, path: &str, id: &str, at: DateTime<Utc>) -> Result<String, String> {
        let folder = sanitize_path(path);
        let mut out = String::new();
        for part in &self.0 {
            match part {
                Part::Literal(s) => out.push_str(s),
                Part::Token(t) => match t {
                    Token::Path => out.push_str(&folder),
                    Token::Id => out.push_str(id),
                    Token::Timestamp => out.push_str(&at.format("%Y%m%dT%H%M%S%.9fZ").to_string()),
                    Token::UnixNanos => {
                        out.push_str(&at.timestamp_nanos_opt().unwrap_or_default().to_string())
                    }
                    Token::Date => out.push_str(&at.format("%Y-%m-%d").to_string()),
                    Token::Year => out.push_str(&at.format("%Y").to_string()),
                    Token::Month => out.push_str(&at.format("%m").to_string()),
                    Token::Day => out.push_str(&at.format("%d").to_string()),
                    Token::Hour => out.push_str(&at.format("%H").to_string()),
                },
            }
        }
        // Collapse empty segments (e.g. from a leading '/' in the template) so
        // names never start with '/' or contain '//'.
        let name = out
            .split('/')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        // Leave room for the longest suffix we append.
        if name.len() + METADATA_SUFFIX.len() > MAX_OBJECT_NAME_LEN {
            return Err(format!(
                "object name would exceed {MAX_OBJECT_NAME_LEN} bytes"
            ));
        }
        Ok(name)
    }
}

/// Convert a request path into a safe GCS "folder".
///
/// - the query string must already be removed
/// - empty, `.` and `..` segments are dropped
/// - characters outside `[A-Za-z0-9._~%=+,@:-]` become `_` (the path is
///   still percent-encoded, so `%` sequences pass through as-is)
/// - an empty result becomes `root`
pub fn sanitize_path(path: &str) -> String {
    let segments: Vec<String> = path
        .split('/')
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .map(|s| {
            s.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || "._~%=+,@:-".contains(c) {
                        c
                    } else {
                        '_'
                    }
                })
                .collect()
        })
        .collect();
    if segments.is_empty() {
        "root".to_string()
    } else {
        segments.join("/")
    }
}

/// File extension for a stored body, based on its `Content-Type`.
pub fn extension_for(content_type: &str) -> &'static str {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match essence.as_str() {
        "application/json" | "text/json" => ".json",
        s if s.ends_with("+json") => ".json",
        "application/x-ndjson" | "application/jsonl" => ".jsonl",
        "application/xml" | "text/xml" => ".xml",
        s if s.ends_with("+xml") => ".xml",
        "application/x-www-form-urlencoded" => ".form",
        "text/plain" => ".txt",
        "text/csv" => ".csv",
        _ => ".bin",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 8, 21, 59, 1).unwrap()
            + chrono::Duration::nanoseconds(123_456_789)
    }

    #[test]
    fn default_template() {
        let tpl = Template::parse(DEFAULT_TEMPLATE).unwrap();
        assert_eq!(
            tpl.render("/webhook_acme/orders", "ID", t()).unwrap(),
            "webhook_acme/orders/dt=2026-11-08/20261108T215901.123456789Z_ID"
        );
    }

    #[test]
    fn unix_nanos_template() {
        let tpl = Template::parse("{path}/ts={unix_nanos}/{id}").unwrap();
        assert_eq!(
            tpl.render("/webhook_acme/", "ID", t()).unwrap(),
            "webhook_acme/ts=1794175141123456789/ID"
        );
    }

    #[test]
    fn all_tokens_and_prefix() {
        let tpl = Template::parse("/raw/{year}/{month}/{day}/{hour}/{path}/{id}").unwrap();
        assert_eq!(
            tpl.render("/", "ID", t()).unwrap(),
            "raw/2026/11/08/21/root/ID"
        );
    }

    #[test]
    fn template_validation() {
        assert!(Template::parse("{path}/{date}").is_err());
        assert!(Template::parse("{path}/{nope}/{id}").is_err());
        assert!(Template::parse("{path}/{id").is_err());
        assert!(Template::parse("{id}/").is_err());
        assert!(Template::parse("{id}").is_ok());
    }

    #[test]
    fn overlong_names_are_rejected() {
        let tpl = Template::parse("{path}/{id}").unwrap();
        let long = format!("/{}", "a".repeat(1100));
        assert!(tpl.render(&long, "ID", t()).is_err());
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_path("/"), "root");
        assert_eq!(sanitize_path(""), "root");
        assert_eq!(sanitize_path("/a/b/"), "a/b");
        assert_eq!(sanitize_path("//a//./../b"), "a/b");
        assert_eq!(sanitize_path("/a b/c*d[e]"), "a_b/c_d_e_");
        assert_eq!(sanitize_path("/caf%C3%A9/x=1"), "caf%C3%A9/x=1");
    }

    #[test]
    fn extensions() {
        assert_eq!(extension_for("application/json"), ".json");
        assert_eq!(extension_for("Application/JSON; charset=utf-8"), ".json");
        assert_eq!(extension_for("application/cloudevents+json"), ".json");
        assert_eq!(extension_for("application/x-www-form-urlencoded"), ".form");
        assert_eq!(extension_for("text/xml"), ".xml");
        assert_eq!(extension_for("application/atom+xml"), ".xml");
        assert_eq!(extension_for("text/plain"), ".txt");
        assert_eq!(extension_for(""), ".bin");
        assert_eq!(extension_for("application/octet-stream"), ".bin");
    }
}
