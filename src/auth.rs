//! Request authentication.
//!
//! Every scheme is configured from environment variables (see `Auth::from_env`)
//! and verified against the request headers and the raw, unparsed body bytes.

use axum::http::{HeaderMap, HeaderName};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{KeyInit, Mac};
use sha2::Digest;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// Default maximum clock skew accepted for timestamped signatures.
pub const DEFAULT_TIMESTAMP_TOLERANCE: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Hex,
    Base64,
}

/// One piece of the string that is signed in generic HMAC mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadPart {
    Literal(String),
    Body,
    Timestamp,
}

#[derive(Debug, Clone)]
pub struct HmacConfig {
    pub header: HeaderName,
    pub secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub encoding: Encoding,
    pub prefix: String,
    pub timestamp_header: Option<HeaderName>,
    pub payload: Vec<PayloadPart>,
    pub tolerance: Duration,
}

#[derive(Debug, Clone)]
pub enum Auth {
    /// No application-level authentication (e.g. Cloud Run IAM does it).
    None,
    /// A shared secret sent verbatim in a header.
    Header { header: HeaderName, secret: Vec<u8> },
    /// An HMAC of the body (optionally with a timestamp) sent in a header.
    Hmac(HmacConfig),
    /// <https://www.standardwebhooks.com/> (also used by Svix).
    StandardWebhooks { key: Vec<u8>, tolerance: Duration },
    /// Stripe's `Stripe-Signature` scheme.
    Stripe {
        secret: Vec<u8>,
        tolerance: Duration,
    },
}

/// Why a request was rejected. Only ever logged, never returned to the caller.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthError(pub String);

impl AuthError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

impl Auth {
    /// Build the authentication config from environment-style lookups.
    pub fn from_env(get: &dyn Fn(&str) -> Option<String>) -> Result<Self, String> {
        let mode = get("AUTH_MODE")
            .ok_or("AUTH_MODE is required: one of none, header, hmac, standard-webhooks, stripe")?;
        let secret = || -> Result<String, String> {
            get("AUTH_SECRET")
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("AUTH_SECRET is required when AUTH_MODE={mode}"))
        };
        let header = || -> Result<HeaderName, String> {
            let raw = get("AUTH_HEADER")
                .ok_or_else(|| format!("AUTH_HEADER is required when AUTH_MODE={mode}"))?;
            HeaderName::try_from(raw.trim())
                .map_err(|_| format!("AUTH_HEADER is not a valid header name: {raw:?}"))
        };
        let tolerance = || -> Result<Duration, String> {
            match get("AUTH_TIMESTAMP_TOLERANCE_SECS") {
                None => Ok(DEFAULT_TIMESTAMP_TOLERANCE),
                Some(s) => s.parse().map(Duration::from_secs).map_err(|_| {
                    format!("AUTH_TIMESTAMP_TOLERANCE_SECS must be an integer, got {s:?}")
                }),
            }
        };

        match mode.as_str() {
            "none" => Ok(Auth::None),
            "header" => Ok(Auth::Header {
                header: header()?,
                secret: secret()?.into_bytes(),
            }),
            "hmac" => {
                let algorithm = match get("AUTH_HMAC_ALGORITHM").as_deref() {
                    None | Some("sha256") => Algorithm::Sha256,
                    Some("sha1") => Algorithm::Sha1,
                    Some("sha512") => Algorithm::Sha512,
                    Some(other) => {
                        return Err(format!(
                            "AUTH_HMAC_ALGORITHM must be sha1, sha256 or sha512, got {other:?}"
                        ));
                    }
                };
                let encoding = match get("AUTH_HMAC_ENCODING").as_deref() {
                    None | Some("hex") => Encoding::Hex,
                    Some("base64") => Encoding::Base64,
                    Some(other) => {
                        return Err(format!(
                            "AUTH_HMAC_ENCODING must be hex or base64, got {other:?}"
                        ));
                    }
                };
                let timestamp_header = match get("AUTH_HMAC_TIMESTAMP_HEADER") {
                    None => None,
                    Some(raw) => Some(HeaderName::try_from(raw.trim()).map_err(|_| {
                        format!("AUTH_HMAC_TIMESTAMP_HEADER is not a valid header name: {raw:?}")
                    })?),
                };
                let template = get("AUTH_HMAC_PAYLOAD").unwrap_or_else(|| "{body}".into());
                let payload = parse_payload_template(&template)?;
                if payload.contains(&PayloadPart::Timestamp) != timestamp_header.is_some() {
                    return Err("AUTH_HMAC_PAYLOAD must contain {timestamp} if and only if \
                         AUTH_HMAC_TIMESTAMP_HEADER is set"
                        .into());
                }
                Ok(Auth::Hmac(HmacConfig {
                    header: header()?,
                    secret: secret()?.into_bytes(),
                    algorithm,
                    encoding,
                    prefix: get("AUTH_HMAC_PREFIX").unwrap_or_default(),
                    timestamp_header,
                    payload,
                    tolerance: tolerance()?,
                }))
            }
            "standard-webhooks" => {
                let raw = secret()?;
                let b64 = raw.strip_prefix("whsec_").unwrap_or(&raw);
                let key = BASE64.decode(b64).map_err(|_| {
                    "AUTH_SECRET for standard-webhooks must be base64, optionally prefixed with \
                     whsec_"
                        .to_string()
                })?;
                Ok(Auth::StandardWebhooks {
                    key,
                    tolerance: tolerance()?,
                })
            }
            "stripe" => Ok(Auth::Stripe {
                secret: secret()?.into_bytes(),
                tolerance: tolerance()?,
            }),
            other => Err(format!(
                "unknown AUTH_MODE {other:?}: expected one of none, header, hmac, \
                 standard-webhooks, stripe"
            )),
        }
    }

    /// Short name of the scheme, recorded in the metadata file.
    pub fn mode(&self) -> &'static str {
        match self {
            Auth::None => "none",
            Auth::Header { .. } => "header",
            Auth::Hmac(_) => "hmac",
            Auth::StandardWebhooks { .. } => "standard-webhooks",
            Auth::Stripe { .. } => "stripe",
        }
    }

    /// The header that carries a plain shared secret, which must never be
    /// written to the bucket.
    pub fn secret_header(&self) -> Option<&HeaderName> {
        match self {
            Auth::Header { header, .. } => Some(header),
            _ => None,
        }
    }

    /// Check everything that can be decided from the headers alone, and start
    /// verifying the body, which is then fed in with [`Pending::update`].
    ///
    /// Header-secret auth is fully decided here, before any body is read.
    pub fn begin(&self, headers: &HeaderMap, now: SystemTime) -> Result<Pending, AuthError> {
        match self {
            Auth::None => Ok(Pending(None)),
            Auth::Header { header, secret } => {
                // Hash both sides so the comparison is constant-time and does
                // not leak the secret's length.
                let expected = sha2::Sha256::digest(secret);
                let ok = headers.get_all(header).iter().any(|v| {
                    let got = sha2::Sha256::digest(v.as_bytes());
                    bool::from(got.as_slice().ct_eq(expected.as_slice()))
                });
                if ok {
                    Ok(Pending(None))
                } else if headers.contains_key(header) {
                    Err(AuthError::new(format!("{header} header does not match")))
                } else {
                    Err(AuthError::new(format!("missing {header} header")))
                }
            }
            Auth::Hmac(cfg) => begin_hmac(cfg, headers, now),
            Auth::StandardWebhooks { key, tolerance } => {
                begin_standard_webhooks(key, *tolerance, headers, now)
            }
            Auth::Stripe { secret, tolerance } => begin_stripe(secret, *tolerance, headers, now),
        }
    }

    /// Verify a complete request in one go.
    #[cfg(test)]
    pub fn verify(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        now: SystemTime,
    ) -> Result<(), AuthError> {
        let mut pending = self.begin(headers, now)?;
        pending.update(body);
        pending.finish()
    }
}

/// An in-progress body signature check. `None` means the request is already
/// authenticated (or needs no body check).
pub struct Pending(Option<Signature>);

struct Signature {
    mac: AnyMac,
    /// Signed bytes that come after the body (e.g. a template suffix).
    suffix: Vec<u8>,
    /// Decoded signatures from the request; any one may match.
    candidates: Vec<Vec<u8>>,
    failure: String,
}

impl Pending {
    pub fn update(&mut self, data: &[u8]) {
        if let Some(sig) = &mut self.0 {
            sig.mac.update(data);
        }
    }

    pub fn finish(self) -> Result<(), AuthError> {
        let Some(mut sig) = self.0 else {
            return Ok(());
        };
        sig.mac.update(&sig.suffix);
        let computed = sig.mac.finalize();
        if sig.candidates.iter().any(|c| ct_eq(c, &computed)) {
            Ok(())
        } else {
            Err(AuthError(sig.failure))
        }
    }
}

enum AnyMac {
    Sha1(hmac::Hmac<sha1::Sha1>),
    Sha256(hmac::Hmac<sha2::Sha256>),
    Sha512(hmac::Hmac<sha2::Sha512>),
}

impl AnyMac {
    fn new(algorithm: Algorithm, key: &[u8]) -> Self {
        const MSG: &str = "HMAC accepts any key length";
        match algorithm {
            Algorithm::Sha1 => AnyMac::Sha1(hmac::Hmac::new_from_slice(key).expect(MSG)),
            Algorithm::Sha256 => AnyMac::Sha256(hmac::Hmac::new_from_slice(key).expect(MSG)),
            Algorithm::Sha512 => AnyMac::Sha512(hmac::Hmac::new_from_slice(key).expect(MSG)),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            AnyMac::Sha1(m) => m.update(data),
            AnyMac::Sha256(m) => m.update(data),
            AnyMac::Sha512(m) => m.update(data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            AnyMac::Sha1(m) => m.finalize().into_bytes().to_vec(),
            AnyMac::Sha256(m) => m.finalize().into_bytes().to_vec(),
            AnyMac::Sha512(m) => m.finalize().into_bytes().to_vec(),
        }
    }
}

fn parse_payload_template(template: &str) -> Result<Vec<PayloadPart>, String> {
    let mut parts = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        if start > 0 {
            parts.push(PayloadPart::Literal(rest[..start].to_string()));
        }
        let end = rest[start..]
            .find('}')
            .ok_or("AUTH_HMAC_PAYLOAD has an unclosed '{'")?
            + start;
        parts.push(match &rest[start + 1..end] {
            "body" => PayloadPart::Body,
            "timestamp" => PayloadPart::Timestamp,
            other => {
                return Err(format!(
                    "AUTH_HMAC_PAYLOAD has unknown placeholder {{{other}}}; \
                     expected {{body}} or {{timestamp}}"
                ));
            }
        });
        rest = &rest[end + 1..];
    }
    if !rest.is_empty() {
        parts.push(PayloadPart::Literal(rest.to_string()));
    }
    if parts.iter().filter(|p| **p == PayloadPart::Body).count() != 1 {
        return Err("AUTH_HMAC_PAYLOAD must contain {body} exactly once".into());
    }
    Ok(parts)
}

/// Compute an HMAC over the concatenation of `chunks`.
#[cfg(test)]
fn hmac(algorithm: Algorithm, key: &[u8], chunks: &[&[u8]]) -> Vec<u8> {
    let mut mac = AnyMac::new(algorithm, key);
    for c in chunks {
        mac.update(c);
    }
    mac.finalize()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
}

/// Parse a unix-seconds timestamp and check it is within `tolerance` of `now`.
fn check_timestamp(raw: &str, tolerance: Duration, now: SystemTime) -> Result<(), AuthError> {
    let ts: u64 = raw
        .parse()
        .map_err(|_| AuthError::new(format!("timestamp {raw:?} is not unix seconds")))?;
    let now = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if now.abs_diff(ts) > tolerance.as_secs() {
        return Err(AuthError::new(format!(
            "timestamp {ts} is outside the {}s tolerance (now {now})",
            tolerance.as_secs()
        )));
    }
    Ok(())
}

fn begin_hmac(
    cfg: &HmacConfig,
    headers: &HeaderMap,
    now: SystemTime,
) -> Result<Pending, AuthError> {
    let timestamp = match &cfg.timestamp_header {
        None => None,
        Some(h) => {
            let ts = header_str(headers, h.as_str())
                .ok_or_else(|| AuthError::new(format!("missing {h} header")))?;
            check_timestamp(ts, cfg.tolerance, now)?;
            Some(ts)
        }
    };

    let values: Vec<&str> = headers
        .get_all(&cfg.header)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if values.is_empty() {
        return Err(AuthError::new(format!("missing {} header", cfg.header)));
    }
    let candidates: Vec<Vec<u8>> = values
        .iter()
        .filter_map(|v| v.trim().strip_prefix(cfg.prefix.as_str()))
        .filter_map(|sig| match cfg.encoding {
            Encoding::Hex => hex::decode(sig.trim()).ok(),
            Encoding::Base64 => BASE64.decode(sig.trim()).ok(),
        })
        .collect();
    if candidates.is_empty() {
        return Err(AuthError::new(format!(
            "{} has no {:?}-encoded signature with prefix {:?}",
            cfg.header, cfg.encoding, cfg.prefix
        )));
    }

    // Sign everything before {body} now; keep what comes after for `finish`.
    let mut mac = AnyMac::new(cfg.algorithm, &cfg.secret);
    let mut suffix = Vec::new();
    let mut after_body = false;
    for part in &cfg.payload {
        let bytes = match part {
            PayloadPart::Body => {
                after_body = true;
                continue;
            }
            PayloadPart::Literal(s) => s.as_bytes(),
            PayloadPart::Timestamp => timestamp.unwrap_or_default().as_bytes(),
        };
        if after_body {
            suffix.extend_from_slice(bytes);
        } else {
            mac.update(bytes);
        }
    }
    Ok(Pending(Some(Signature {
        mac,
        suffix,
        candidates,
        failure: format!("{} signature does not match", cfg.header),
    })))
}

fn begin_standard_webhooks(
    key: &[u8],
    tolerance: Duration,
    headers: &HeaderMap,
    now: SystemTime,
) -> Result<Pending, AuthError> {
    // Svix sends the same scheme under `svix-*` header names.
    let get = |name: &str| {
        header_str(headers, &format!("webhook-{name}"))
            .or_else(|| header_str(headers, &format!("svix-{name}")))
            .ok_or_else(|| AuthError::new(format!("missing webhook-{name} header")))
    };
    let id = get("id")?;
    let timestamp = get("timestamp")?;
    let signatures = get("signature")?;
    check_timestamp(timestamp, tolerance, now)?;

    let candidates: Vec<Vec<u8>> = signatures
        .split_whitespace()
        .filter_map(|entry| entry.strip_prefix("v1,"))
        .filter_map(|sig| BASE64.decode(sig).ok())
        .collect();
    if candidates.is_empty() {
        return Err(AuthError::new("webhook-signature has no v1 signature"));
    }
    let mut mac = AnyMac::new(Algorithm::Sha256, key);
    for part in [id.as_bytes(), b".", timestamp.as_bytes(), b"."] {
        mac.update(part);
    }
    Ok(Pending(Some(Signature {
        mac,
        suffix: Vec::new(),
        candidates,
        failure: "webhook-signature does not match".into(),
    })))
}

fn begin_stripe(
    secret: &[u8],
    tolerance: Duration,
    headers: &HeaderMap,
    now: SystemTime,
) -> Result<Pending, AuthError> {
    let header = header_str(headers, "stripe-signature")
        .ok_or_else(|| AuthError::new("missing stripe-signature header"))?;
    let mut timestamp = None;
    let mut candidates = Vec::new();
    for item in header.split(',') {
        match item.trim().split_once('=') {
            Some(("t", t)) => timestamp = Some(t),
            Some(("v1", s)) => candidates.extend(hex::decode(s).ok()),
            _ => {}
        }
    }
    let timestamp = timestamp.ok_or_else(|| AuthError::new("stripe-signature has no t="))?;
    check_timestamp(timestamp, tolerance, now)?;
    if candidates.is_empty() {
        return Err(AuthError::new("stripe-signature has no v1 signature"));
    }
    let mut mac = AnyMac::new(Algorithm::Sha256, secret);
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    Ok(Pending(Some(Signature {
        mac,
        suffix: Vec::new(),
        candidates,
        failure: "stripe-signature does not match".into(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                HeaderName::try_from(*k).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn auth_mode_is_required() {
        assert!(Auth::from_env(&env(&[])).is_err());
    }

    #[test]
    fn unknown_mode_is_rejected() {
        let err = Auth::from_env(&env(&[("AUTH_MODE", "magic")])).unwrap_err();
        assert!(err.contains("unknown AUTH_MODE"));
    }

    #[test]
    fn none_accepts_anything() {
        let auth = Auth::from_env(&env(&[("AUTH_MODE", "none")])).unwrap();
        assert!(auth.verify(&HeaderMap::new(), b"", at(0)).is_ok());
    }

    #[test]
    fn header_mode_requires_header_and_secret() {
        assert!(Auth::from_env(&env(&[("AUTH_MODE", "header"), ("AUTH_SECRET", "s")])).is_err());
        assert!(
            Auth::from_env(&env(&[("AUTH_MODE", "header"), ("AUTH_HEADER", "X-Key")])).is_err()
        );
        assert!(
            Auth::from_env(&env(&[
                ("AUTH_MODE", "header"),
                ("AUTH_HEADER", "X-Key"),
                ("AUTH_SECRET", "")
            ]))
            .is_err()
        );
    }

    #[test]
    fn header_mode_verifies_secret() {
        let auth = Auth::from_env(&env(&[
            ("AUTH_MODE", "header"),
            ("AUTH_HEADER", "Acme-Webhook-Secret"),
            ("AUTH_SECRET", "hunter2"),
        ]))
        .unwrap();
        let now = at(0);
        assert!(
            auth.verify(&headers(&[("acme-webhook-secret", "hunter2")]), b"", now)
                .is_ok()
        );
        assert!(
            auth.verify(&headers(&[("acme-webhook-secret", "hunter3")]), b"", now)
                .is_err()
        );
        assert!(
            auth.verify(&headers(&[("acme-webhook-secret", "hunter")]), b"", now)
                .is_err()
        );
        assert_eq!(
            auth.verify(&HeaderMap::new(), b"", now).unwrap_err(),
            AuthError::new("missing acme-webhook-secret header")
        );
        assert_eq!(
            auth.secret_header().map(|h| h.as_str()),
            Some("acme-webhook-secret")
        );
    }

    #[test]
    fn header_mode_supports_bearer_tokens() {
        let auth = Auth::from_env(&env(&[
            ("AUTH_MODE", "header"),
            ("AUTH_HEADER", "Authorization"),
            ("AUTH_SECRET", "Bearer abc"),
        ]))
        .unwrap();
        assert!(
            auth.verify(&headers(&[("authorization", "Bearer abc")]), b"", at(0))
                .is_ok()
        );
    }

    /// GitHub: `X-Hub-Signature-256: sha256=<hex hmac-sha256(body)>`.
    #[test]
    fn hmac_github_style() {
        let auth = Auth::from_env(&env(&[
            ("AUTH_MODE", "hmac"),
            ("AUTH_HEADER", "X-Hub-Signature-256"),
            ("AUTH_HMAC_PREFIX", "sha256="),
            ("AUTH_SECRET", "It's a Secret to Everybody"),
        ]))
        .unwrap();
        // Test vector from GitHub's "Validating webhook deliveries" docs.
        let sig = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        let body = b"Hello, World!";
        assert!(
            auth.verify(&headers(&[("x-hub-signature-256", sig)]), body, at(0))
                .is_ok()
        );
        assert!(
            auth.verify(
                &headers(&[("x-hub-signature-256", sig)]),
                b"tampered",
                at(0)
            )
            .is_err()
        );
        assert!(auth.verify(&HeaderMap::new(), body, at(0)).is_err());
    }

    #[test]
    fn hmac_base64_sha1_and_sha512() {
        for (algo, encoding) in [("sha1", "base64"), ("sha512", "hex"), ("sha256", "base64")] {
            let auth = Auth::from_env(&env(&[
                ("AUTH_MODE", "hmac"),
                ("AUTH_HEADER", "X-Sig"),
                ("AUTH_SECRET", "k"),
                ("AUTH_HMAC_ALGORITHM", algo),
                ("AUTH_HMAC_ENCODING", encoding),
            ]))
            .unwrap();
            let Auth::Hmac(cfg) = &auth else {
                unreachable!()
            };
            let mac = hmac(cfg.algorithm, b"k", &[b"payload"]);
            let sig = match encoding {
                "hex" => hex::encode(&mac),
                _ => BASE64.encode(&mac),
            };
            assert!(
                auth.verify(&headers(&[("x-sig", &sig)]), b"payload", at(0))
                    .is_ok(),
                "{algo}/{encoding}"
            );
        }
    }

    /// Slack: `X-Slack-Signature: v0=<hex hmac-sha256("v0:{ts}:{body}")>`.
    #[test]
    fn hmac_slack_style_with_timestamp() {
        let auth = Auth::from_env(&env(&[
            ("AUTH_MODE", "hmac"),
            ("AUTH_HEADER", "X-Slack-Signature"),
            ("AUTH_HMAC_PREFIX", "v0="),
            ("AUTH_HMAC_TIMESTAMP_HEADER", "X-Slack-Request-Timestamp"),
            ("AUTH_HMAC_PAYLOAD", "v0:{timestamp}:{body}"),
            ("AUTH_SECRET", "8f742231b10e8888abcd99yyyzzz85a5"),
        ]))
        .unwrap();
        // Test vector from Slack's "Verifying requests from Slack" docs.
        let body = b"token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
        let h = headers(&[
            ("x-slack-request-timestamp", "1531420618"),
            (
                "x-slack-signature",
                "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503",
            ),
        ]);
        assert!(auth.verify(&h, body, at(1531420618 + 10)).is_ok());
        // Replayed outside the tolerance window.
        assert!(auth.verify(&h, body, at(1531420618 + 301)).is_err());
    }

    #[test]
    fn hmac_template_validation() {
        let base = [
            ("AUTH_MODE", "hmac"),
            ("AUTH_HEADER", "X-Sig"),
            ("AUTH_SECRET", "k"),
        ];
        let with = |extra: &[(&'static str, &'static str)]| {
            let mut all = base.to_vec();
            all.extend_from_slice(extra);
            Auth::from_env(&env(&all))
        };
        assert!(with(&[("AUTH_HMAC_PAYLOAD", "{timestamp}")]).is_err());
        assert!(with(&[("AUTH_HMAC_PAYLOAD", "{body}{body}")]).is_err());
        assert!(with(&[("AUTH_HMAC_PAYLOAD", "{bogus}{body}")]).is_err());
        assert!(with(&[("AUTH_HMAC_PAYLOAD", "{body")]).is_err());
        // {timestamp} without a timestamp header, and vice versa.
        assert!(with(&[("AUTH_HMAC_PAYLOAD", "{timestamp}.{body}")]).is_err());
        assert!(with(&[("AUTH_HMAC_TIMESTAMP_HEADER", "X-Ts")]).is_err());
        assert!(with(&[("AUTH_HMAC_ALGORITHM", "md5")]).is_err());
        assert!(with(&[("AUTH_HMAC_ENCODING", "base32")]).is_err());
        assert!(with(&[]).is_ok());
    }

    #[test]
    fn signature_is_computed_incrementally() {
        let auth = Auth::from_env(&env(&[
            ("AUTH_MODE", "hmac"),
            ("AUTH_HEADER", "X-Sig"),
            ("AUTH_SECRET", "k"),
            ("AUTH_HMAC_TIMESTAMP_HEADER", "X-Ts"),
            ("AUTH_HMAC_PAYLOAD", "pre:{timestamp}:{body}:post"),
        ]))
        .unwrap();
        let body = b"a body that arrives in several pieces";
        let sig = hex::encode(hmac(
            Algorithm::Sha256,
            b"k",
            &[b"pre:", b"100", b":", body, b":post"],
        ));
        let h = headers(&[("x-sig", &sig), ("x-ts", "100")]);
        let mut pending = auth.begin(&h, at(100)).unwrap();
        for piece in body.chunks(5) {
            pending.update(piece);
        }
        assert!(pending.finish().is_ok());

        let mut pending = auth.begin(&h, at(100)).unwrap();
        pending.update(&body[..10]);
        assert!(pending.finish().is_err(), "truncated body");
    }

    #[test]
    fn undecodable_signatures_fail_before_the_body() {
        let auth = Auth::from_env(&env(&[
            ("AUTH_MODE", "hmac"),
            ("AUTH_HEADER", "X-Sig"),
            ("AUTH_SECRET", "k"),
        ]))
        .unwrap();
        assert!(
            auth.begin(&headers(&[("x-sig", "not hex")]), at(0))
                .is_err()
        );
    }

    #[test]
    fn payload_template_parses() {
        assert_eq!(
            parse_payload_template("v0:{timestamp}:{body}").unwrap(),
            vec![
                PayloadPart::Literal("v0:".into()),
                PayloadPart::Timestamp,
                PayloadPart::Literal(":".into()),
                PayloadPart::Body,
            ]
        );
    }

    #[test]
    fn standard_webhooks_spec_vector() {
        let auth = Auth::from_env(&env(&[
            ("AUTH_MODE", "standard-webhooks"),
            ("AUTH_SECRET", "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"),
        ]))
        .unwrap();
        let body = br#"{"test": 2432232314}"#;
        let ts = 1614265330;
        let good = headers(&[
            ("webhook-id", "msg_p5jXN8AQM9LWM0D4loKWxJek"),
            ("webhook-timestamp", "1614265330"),
            (
                "webhook-signature",
                "v1,bm9ldHUjKzFob2VudXRob2VodWUzMjRvdWVvdW9ldQo= v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
            ),
        ]);
        assert!(auth.verify(&good, body, at(ts)).is_ok());
        assert!(auth.verify(&good, b"{}", at(ts)).is_err());
        assert!(auth.verify(&good, body, at(ts + 1000)).is_err());

        // Svix header names are accepted too.
        let svix = headers(&[
            ("svix-id", "msg_p5jXN8AQM9LWM0D4loKWxJek"),
            ("svix-timestamp", "1614265330"),
            (
                "svix-signature",
                "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=",
            ),
        ]);
        assert!(auth.verify(&svix, body, at(ts)).is_ok());
    }

    #[test]
    fn standard_webhooks_rejects_non_base64_secret() {
        assert!(
            Auth::from_env(&env(&[
                ("AUTH_MODE", "standard-webhooks"),
                ("AUTH_SECRET", "whsec_!!!")
            ]))
            .is_err()
        );
    }

    #[test]
    fn stripe_signature() {
        let auth = Auth::from_env(&env(&[
            ("AUTH_MODE", "stripe"),
            ("AUTH_SECRET", "whsec_test_secret"),
        ]))
        .unwrap();
        let body = br#"{"id":"evt_1"}"#;
        let ts = 1700000000u64;
        let sig = hex::encode(hmac(
            Algorithm::Sha256,
            b"whsec_test_secret",
            &[ts.to_string().as_bytes(), b".", body],
        ));
        let header = format!("t={ts},v1=deadbeef,v1={sig},v0=ignored");
        let h = headers(&[("stripe-signature", &header)]);
        assert!(auth.verify(&h, body, at(ts + 5)).is_ok());
        assert!(auth.verify(&h, b"{}", at(ts + 5)).is_err());
        assert!(auth.verify(&h, body, at(ts + 600)).is_err());
        assert!(
            auth.verify(&headers(&[("stripe-signature", "v1=abc")]), body, at(ts))
                .is_err()
        );
    }

    #[test]
    fn tolerance_is_configurable() {
        let auth = Auth::from_env(&env(&[
            ("AUTH_MODE", "stripe"),
            ("AUTH_SECRET", "s"),
            ("AUTH_TIMESTAMP_TOLERANCE_SECS", "10"),
        ]))
        .unwrap();
        assert!(matches!(auth, Auth::Stripe { tolerance, .. } if tolerance.as_secs() == 10));
        assert!(
            Auth::from_env(&env(&[
                ("AUTH_MODE", "stripe"),
                ("AUTH_SECRET", "s"),
                ("AUTH_TIMESTAMP_TOLERANCE_SECS", "ten"),
            ]))
            .is_err()
        );
    }
}
