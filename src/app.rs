//! HTTP routing and the webhook handler.

use crate::auth::{AuthError, Pending};
use crate::config::Config;
use crate::log;
use crate::naming::{METADATA_SUFFIX, extension_for};
use crate::storage::{NewObject, ObjectStore, StoreError, Upload};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use bytes::BytesMut;
use chrono::{SecondsFormat, Utc};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn ObjectStore>,
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .fallback(handle_webhook)
        .with_state(state)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

async fn handle_webhook(State(state): State<AppState>, req: Request) -> Response {
    let config = &state.config;
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let remote_addr = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.to_string());

    if !config.path_matches(&path) {
        return error(StatusCode::NOT_FOUND, "not found");
    }
    if !config.methods.contains(&parts.method) {
        let allow = config
            .methods
            .iter()
            .map(|m| m.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let mut resp = error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        if let Ok(v) = HeaderValue::from_str(&allow) {
            resp.headers_mut().insert(header::ALLOW, v);
        }
        return resp;
    }

    let received_at = Utc::now();

    // Header-only checks (shared secrets, timestamps) happen before any of the
    // body is read; body signatures are computed while it streams in.
    let mut pending_auth = match config.auth.begin(&parts.headers, SystemTime::now()) {
        Ok(p) => p,
        Err(e) => return unauthorized(config, &path, &remote_addr, e),
    };

    let declared_len = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared_len.is_some_and(|n| n > config.max_body_bytes as u64) {
        return too_large(config, &path, &remote_addr);
    }

    let id = uuid::Uuid::now_v7().to_string();
    let base = match config.template.render(&path, &id, received_at) {
        Ok(b) => b,
        Err(e) => {
            log::warning(
                "Webhook rejected: cannot build object name",
                json!({ "path": path, "error": e }),
            );
            return error(StatusCode::BAD_REQUEST, "request path is too long");
        }
    };

    let header_str = |name| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let content_type =
        header_str(header::CONTENT_TYPE).unwrap_or_else(|| "application/octet-stream".into());
    let body_object = NewObject {
        name: format!("{base}{}", extension_for(&content_type)),
        content_type,
        // Stored as-is (never decompressed); GCS records the encoding so
        // downloads can be transparently decoded.
        content_encoding: header_str(header::CONTENT_ENCODING),
    };
    let metadata_object = NewObject {
        name: format!("{base}{METADATA_SUFFIX}"),
        content_type: "application/json".into(),
        content_encoding: None,
    };

    let received =
        match receive_body(body, config, &*state.store, &body_object, &mut pending_auth).await {
            Ok(r) => r,
            Err(BodyError::TooLarge) => return too_large(config, &path, &remote_addr),
            Err(BodyError::Read(e)) => {
                log::warning(
                    "Failed to read webhook body",
                    json!({ "path": path, "error": e, "remote_addr": remote_addr }),
                );
                return error(StatusCode::BAD_REQUEST, "failed to read body");
            }
            Err(BodyError::Store(e)) => {
                log::error(
                    "Failed to store webhook",
                    json!({ "id": id, "path": path, "error": e.0 }),
                );
                return error(StatusCode::SERVICE_UNAVAILABLE, "failed to store webhook");
            }
        };

    if let Err(e) = pending_auth.finish() {
        abort(received.upload).await;
        return unauthorized(config, &path, &remote_addr, e);
    }

    let bucket = state.store.bucket().to_string();
    let metadata = json!({
        "id": id,
        "received_at": received_at.to_rfc3339_opts(SecondsFormat::Nanos, true),
        "received_at_unix_nanos": received_at.timestamp_nanos_opt(),
        "method": parts.method.as_str(),
        "path": path,
        "query": parts.uri.query(),
        "remote_addr": remote_addr,
        "headers": headers_json(&parts.headers, config),
        "auth_mode": config.auth.mode(),
        "body": {
            "bucket": bucket,
            "object": body_object.name,
            "uri": format!("gs://{bucket}/{}", body_object.name),
            "content_type": body_object.content_type,
            "content_encoding": body_object.content_encoding,
            "size": received.size,
            "sha256": received.sha256,
        },
        "receiver": {
            "name": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
        },
    });
    let metadata_bytes = Bytes::from(serde_json::to_vec_pretty(&metadata).unwrap_or_default());
    let streamed = received.upload.is_some();

    // Run the final writes on their own task so they still complete if the
    // caller disconnects now. The body is written first, so the presence of
    // the metadata object implies the body is complete.
    let store = state.store.clone();
    let (body_obj, meta_obj) = (body_object.clone(), metadata_object.clone());
    let write = tokio::spawn(async move {
        match received.upload {
            Some(upload) => upload.finish(received.tail).await?,
            None => store.put(&body_obj, received.tail).await?,
        }
        store.put(&meta_obj, metadata_bytes).await
    });

    match write.await {
        Ok(Ok(())) => {
            log::info(
                "Webhook stored",
                json!({
                    "id": id,
                    "path": path,
                    "size": received.size,
                    "streamed": streamed,
                    "body_object": format!("gs://{bucket}/{}", body_object.name),
                    "metadata_object": format!("gs://{bucket}/{}", metadata_object.name),
                }),
            );
            (StatusCode::OK, Json(json!({ "id": id }))).into_response()
        }
        Ok(Err(e)) => {
            log::error(
                "Failed to store webhook",
                json!({ "id": id, "path": path, "error": e.0 }),
            );
            error(StatusCode::SERVICE_UNAVAILABLE, "failed to store webhook")
        }
        Err(e) => {
            log::error(
                "Webhook write task failed",
                json!({ "id": id, "path": path, "error": e.to_string() }),
            );
            error(StatusCode::SERVICE_UNAVAILABLE, "failed to store webhook")
        }
    }
}

fn unauthorized(
    config: &Config,
    path: &str,
    remote_addr: &Option<String>,
    e: AuthError,
) -> Response {
    log::warning(
        "Webhook rejected: authentication failed",
        json!({
            "path": path,
            "auth_mode": config.auth.mode(),
            "reason": e.0,
            "remote_addr": remote_addr,
        }),
    );
    error(StatusCode::UNAUTHORIZED, "unauthorized")
}

fn too_large(config: &Config, path: &str, remote_addr: &Option<String>) -> Response {
    log::warning(
        "Webhook body too large",
        json!({ "path": path, "limit": config.max_body_bytes, "remote_addr": remote_addr }),
    );
    error(StatusCode::PAYLOAD_TOO_LARGE, "payload too large")
}

enum BodyError {
    TooLarge,
    Read(String),
    Store(StoreError),
}

/// A fully received body, minus anything already streamed to `upload`.
struct Received {
    /// Bytes not yet written. Never empty when `upload` is set.
    tail: Bytes,
    /// Set once the body outgrew one chunk and streaming began.
    upload: Option<Box<dyn Upload>>,
    size: u64,
    sha256: String,
}

async fn abort(upload: Option<Box<dyn Upload>>) {
    if let Some(u) = upload {
        u.abort().await;
    }
}

/// Read the body, feeding it to the signature check and hasher as it arrives.
///
/// Bodies up to `upload_chunk_bytes` stay in memory. Larger ones are streamed
/// into a chunked upload, holding back the final chunk: the object is only
/// created when the caller finishes the upload after authentication passes.
async fn receive_body(
    body: Body,
    config: &Config,
    store: &dyn ObjectStore,
    object: &NewObject,
    auth: &mut Pending,
) -> Result<Received, BodyError> {
    let chunk = config.upload_chunk_bytes;
    let mut body = Limited::new(body, config.max_body_bytes);
    let mut buf = BytesMut::new();
    let mut upload: Option<Box<dyn Upload>> = None;
    let mut size = 0u64;
    let mut hasher = Sha256::new();

    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                abort(upload).await;
                return Err(if e.downcast_ref::<LengthLimitError>().is_some() {
                    BodyError::TooLarge
                } else {
                    BodyError::Read(e.to_string())
                });
            }
        };
        let Ok(data) = frame.into_data() else {
            continue; // trailers
        };
        hasher.update(&data);
        auth.update(&data);
        size += data.len() as u64;
        buf.extend_from_slice(&data);

        // Strictly greater: always keep at least one byte for the final chunk.
        while buf.len() > chunk {
            let up = match &mut upload {
                Some(u) => u,
                None => upload.insert(store.start_upload(object).await.map_err(BodyError::Store)?),
            };
            if let Err(e) = up.write(buf.split_to(chunk).freeze()).await {
                abort(upload).await;
                return Err(BodyError::Store(e));
            }
        }
    }

    Ok(Received {
        tail: buf.freeze(),
        upload,
        size,
        sha256: hex::encode(hasher.finalize()),
    })
}

/// All request headers as `{name: [values...]}`, with sensitive ones redacted.
fn headers_json(headers: &HeaderMap, config: &Config) -> Value {
    let mut out: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (name, value) in headers {
        let v = if config.redact_headers.contains(name) {
            "[REDACTED]".to_string()
        } else {
            String::from_utf8_lossy(value.as_bytes()).into_owned()
        };
        out.entry(name.as_str()).or_default().push(v);
    }
    json!(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::memory::MemoryStore;
    use axum::body::Body;
    use axum::http::Request;
    use std::collections::HashMap;
    use tower::util::ServiceExt;

    fn config(pairs: &[(&str, &str)]) -> Config {
        let mut map: HashMap<String, String> = [
            ("GCS_BUCKET", "test-bucket"),
            ("AUTH_MODE", "header"),
            ("AUTH_HEADER", "Acme-Webhook-Secret"),
            ("AUTH_SECRET", "s3cret"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        for (k, v) in pairs {
            map.insert(k.to_string(), v.to_string());
        }
        Config::from_lookup(&move |k| map.get(k).cloned()).unwrap()
    }

    fn setup(pairs: &[(&str, &str)], store: MemoryStore) -> (Router, MemoryStore) {
        let state = AppState {
            config: Arc::new(config(pairs)),
            store: Arc::new(store.clone()),
        };
        (app(state), store)
    }

    fn post(uri: &str) -> axum::http::request::Builder {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .extension(ConnectInfo(SocketAddr::from(([10, 0, 0, 1], 5555))))
    }

    async fn body_json(resp: Response) -> Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let (app, _) = setup(&[], MemoryStore::default());
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn stores_body_and_metadata() {
        let (app, store) = setup(&[], MemoryStore::default());
        let resp = app
            .oneshot(
                post("/webhook_acme/orders?x=1")
                    .header("acme-webhook-secret", "s3cret")
                    .header("x-delivery-id", "abc")
                    .header("cookie", "session=1")
                    .body(Body::from(r#"{"order":42}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let id = body_json(resp).await["id"].as_str().unwrap().to_string();

        let objects = store.objects();
        assert_eq!(objects.len(), 2, "body then metadata");
        assert!(store.chunks().is_empty(), "small bodies are not streamed");

        let body = &objects[0];
        let body_name = &body.name;
        assert!(body_name.starts_with("webhook_acme/orders/dt="));
        assert!(body_name.ends_with(&format!("_{id}.json")));
        assert_eq!(body.content_type, "application/json");
        assert_eq!(body.content_encoding, None);
        assert_eq!(&body.data[..], br#"{"order":42}"#);

        let meta = &objects[1];
        assert_eq!(
            meta.name,
            body_name.replace(".json", ".meta.json"),
            "metadata sits next to the body"
        );
        assert_eq!(meta.content_type, "application/json");
        let meta: Value = serde_json::from_slice(&meta.data).unwrap();
        assert_eq!(meta["id"], id.as_str());
        assert_eq!(meta["method"], "POST");
        assert_eq!(meta["path"], "/webhook_acme/orders");
        assert_eq!(meta["query"], "x=1");
        assert_eq!(meta["remote_addr"], "10.0.0.1:5555");
        assert_eq!(meta["auth_mode"], "header");
        assert_eq!(meta["headers"]["x-delivery-id"], json!(["abc"]));
        assert_eq!(
            meta["headers"]["acme-webhook-secret"],
            json!(["[REDACTED]"])
        );
        assert_eq!(meta["headers"]["cookie"], json!(["[REDACTED]"]));
        assert_eq!(meta["body"]["object"], body_name.as_str());
        assert_eq!(
            meta["body"]["uri"],
            format!("gs://test-bucket/{body_name}").as_str()
        );
        assert_eq!(meta["body"]["size"], 12);
        assert_eq!(
            meta["body"]["sha256"],
            hex::encode(Sha256::digest(br#"{"order":42}"#)).as_str()
        );
        assert!(meta["received_at"].as_str().unwrap().ends_with('Z'));
    }

    #[tokio::test]
    async fn rejects_bad_secret() {
        let (app, store) = setup(&[], MemoryStore::default());
        let resp = app
            .oneshot(
                post("/hook")
                    .header("acme-webhook-secret", "wrong")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(store.objects().is_empty());
    }

    #[tokio::test]
    async fn rejects_missing_secret() {
        let (app, store) = setup(&[], MemoryStore::default());
        let resp = app
            .oneshot(post("/hook").body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(store.objects().is_empty());
    }

    #[tokio::test]
    async fn rejects_disallowed_method() {
        let (app, _) = setup(&[], MemoryStore::default());
        let resp = app
            .oneshot(Request::get("/hook").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(resp.headers()["allow"], "POST");
    }

    #[tokio::test]
    async fn allows_configured_methods() {
        let (app, store) = setup(&[("ALLOWED_METHODS", "POST,PUT")], MemoryStore::default());
        let resp = app
            .oneshot(
                Request::put("/hook")
                    .header("acme-webhook-secret", "s3cret")
                    .body(Body::from("hi"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let objects = store.objects();
        // No content-type: stored as octet-stream with a .bin extension.
        assert!(objects[0].name.ends_with(".bin"));
        assert_eq!(objects[0].content_type, "application/octet-stream");
    }

    #[tokio::test]
    async fn paths_outside_prefix_are_not_found() {
        let (app, _) = setup(
            &[("WEBHOOK_PATH_PREFIX", "/webhook_acme/")],
            MemoryStore::default(),
        );
        let resp = app
            .oneshot(
                post("/other")
                    .header("acme-webhook-secret", "s3cret")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn root_path_is_stored_under_root() {
        let (app, store) = setup(&[], MemoryStore::default());
        let resp = app
            .oneshot(
                post("/")
                    .header("acme-webhook-secret", "s3cret")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(store.objects()[0].name.starts_with("root/dt="));
    }

    #[tokio::test]
    async fn rejects_oversized_body() {
        let (app, store) = setup(&[("MAX_BODY_BYTES", "8")], MemoryStore::default());
        let resp = app
            .oneshot(
                post("/hook")
                    .header("acme-webhook-secret", "s3cret")
                    .body(Body::from("123456789"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(store.objects().is_empty());
    }

    #[tokio::test]
    async fn storage_failure_returns_503() {
        let store = MemoryStore {
            fail_suffix: Some(".json"),
            ..Default::default()
        };
        let (app, _) = setup(&[], store);
        let resp = app
            .oneshot(
                post("/hook")
                    .header("acme-webhook-secret", "s3cret")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn metadata_failure_returns_503() {
        let store = MemoryStore {
            fail_suffix: Some(METADATA_SUFFIX),
            ..Default::default()
        };
        let (app, store) = setup(&[], store);
        let resp = app
            .oneshot(
                post("/hook")
                    .header("acme-webhook-secret", "s3cret")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        // The body was written but no metadata, so the delivery is incomplete.
        assert_eq!(store.objects().len(), 1);
    }

    #[tokio::test]
    async fn hmac_is_checked_against_raw_body() {
        let (app, store) = setup(
            &[
                ("AUTH_MODE", "hmac"),
                ("AUTH_HEADER", "X-Hub-Signature-256"),
                ("AUTH_HMAC_PREFIX", "sha256="),
                ("AUTH_SECRET", "It's a Secret to Everybody"),
            ],
            MemoryStore::default(),
        );
        let sig = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        let resp = app
            .clone()
            .oneshot(
                post("/github")
                    .header("x-hub-signature-256", sig)
                    .body(Body::from("Hello, World!"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let meta: Value = serde_json::from_slice(&store.objects()[1].data).unwrap();
        // Signatures are kept (they are not secrets) so deliveries can be re-verified.
        assert_eq!(meta["headers"]["x-hub-signature-256"], json!([sig]));

        let resp = app
            .oneshot(
                post("/github")
                    .header("x-hub-signature-256", sig)
                    .body(Body::from("Hello, World?"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn repeated_headers_are_all_kept() {
        let (app, store) = setup(&[], MemoryStore::default());
        app.oneshot(
            post("/hook")
                .header("acme-webhook-secret", "s3cret")
                .header("x-tag", "a")
                .header("x-tag", "b")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
        let meta: Value = serde_json::from_slice(&store.objects()[1].data).unwrap();
        assert_eq!(meta["headers"]["x-tag"], json!(["a", "b"]));
    }

    const CHUNK: usize = crate::storage::CHUNK_GRANULARITY;

    fn big_body(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[tokio::test]
    async fn large_bodies_are_streamed_in_chunks() {
        let chunk = CHUNK.to_string();
        let (app, store) = setup(&[("UPLOAD_CHUNK_BYTES", &chunk)], MemoryStore::default());
        let data = big_body(2 * CHUNK + 100);
        let resp = app
            .oneshot(
                post("/big")
                    .header("acme-webhook-secret", "s3cret")
                    .body(Body::from(data.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(store.chunks(), vec![CHUNK, CHUNK, 100]);
        let objects = store.objects();
        assert_eq!(objects[0].data, data);
        let meta: Value = serde_json::from_slice(&objects[1].data).unwrap();
        assert_eq!(meta["body"]["size"], data.len());
        assert_eq!(
            meta["body"]["sha256"],
            hex::encode(Sha256::digest(&data)).as_str()
        );
    }

    #[tokio::test]
    async fn final_chunk_is_never_empty() {
        let chunk = CHUNK.to_string();
        // Exactly one chunk: fits in memory, written in one request.
        let (app, store) = setup(&[("UPLOAD_CHUNK_BYTES", &chunk)], MemoryStore::default());
        let req = |len| {
            post("/big")
                .header("acme-webhook-secret", "s3cret")
                .body(Body::from(big_body(len)))
                .unwrap()
        };
        let resp = app.clone().oneshot(req(CHUNK)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(store.chunks().is_empty());

        // Exactly two chunks: the second is held back as the final one.
        let resp = app.oneshot(req(2 * CHUNK)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(store.chunks(), vec![CHUNK, CHUNK]);
        assert_eq!(store.objects()[2].data.len(), 2 * CHUNK);
    }

    #[tokio::test]
    async fn bad_signature_on_streamed_body_creates_nothing() {
        let chunk = CHUNK.to_string();
        let (app, store) = setup(
            &[
                ("UPLOAD_CHUNK_BYTES", &chunk),
                ("AUTH_MODE", "hmac"),
                ("AUTH_HEADER", "X-Sig"),
                ("AUTH_SECRET", "k"),
            ],
            MemoryStore::default(),
        );
        let resp = app
            .oneshot(
                post("/big")
                    .header("x-sig", "00ff")
                    .body(Body::from(big_body(3 * CHUNK)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            store.chunks(),
            vec![CHUNK, CHUNK],
            "streamed before the check"
        );
        assert_eq!(store.aborted(), 1);
        assert!(store.objects().is_empty());
    }

    #[tokio::test]
    async fn streamed_storage_failure_returns_503() {
        let chunk = CHUNK.to_string();
        let store = MemoryStore {
            fail_suffix: Some(".json"),
            ..Default::default()
        };
        let (app, store) = setup(&[("UPLOAD_CHUNK_BYTES", &chunk)], store);
        let resp = app
            .oneshot(
                post("/big")
                    .header("acme-webhook-secret", "s3cret")
                    .body(Body::from(big_body(2 * CHUNK)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(store.objects().is_empty());
    }

    /// A body that fails if it is ever read.
    struct UnreadableBody;

    impl axum::body::HttpBody for UnreadableBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            panic!("body was read");
        }
    }

    #[tokio::test]
    async fn header_auth_rejects_before_reading_body() {
        let (app, _) = setup(&[], MemoryStore::default());
        let resp = app
            .oneshot(
                post("/hook")
                    .header("acme-webhook-secret", "wrong")
                    .body(Body::new(UnreadableBody))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn declared_length_over_limit_is_rejected_up_front() {
        let (app, _) = setup(&[("MAX_BODY_BYTES", "8")], MemoryStore::default());
        let resp = app
            .oneshot(
                post("/hook")
                    .header("acme-webhook-secret", "s3cret")
                    .header("content-length", "9")
                    .body(Body::new(UnreadableBody))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn content_encoding_is_kept_not_decoded() {
        let (app, store) = setup(&[], MemoryStore::default());
        let compressed = b"\x1f\x8b\x08\x00not-really-gzip".to_vec();
        let resp = app
            .oneshot(
                post("/hook")
                    .header("acme-webhook-secret", "s3cret")
                    .header("content-encoding", "gzip")
                    .body(Body::from(compressed.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let objects = store.objects();
        assert_eq!(objects[0].data, compressed);
        assert_eq!(objects[0].content_encoding.as_deref(), Some("gzip"));
        let meta: Value = serde_json::from_slice(&objects[1].data).unwrap();
        assert_eq!(meta["body"]["content_encoding"], "gzip");
    }
}
