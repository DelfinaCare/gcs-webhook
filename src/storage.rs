//! Minimal Google Cloud Storage writer.
//!
//! Small objects use the JSON API "simple upload": one request per object.
//! Large request bodies use a resumable upload, so they are streamed to GCS in
//! chunks instead of being held in memory. A resumable upload only creates the
//! object when its final chunk is sent, so it can be abandoned (e.g. when a
//! signature turns out to be wrong) without anything appearing in the bucket.
//!
//! Every upload sets `ifGenerationMatch=0`, so an existing object is never
//! overwritten and the service account only needs `roles/storage.objectCreator`.

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Method, Request, StatusCode};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

const GCS_ENDPOINT: &str = "https://storage.googleapis.com";
const SCOPES: &[&str] = &["https://www.googleapis.com/auth/devstorage.read_write"];

/// Resumable upload chunks (except the last) must be a multiple of this.
pub const CHUNK_GRANULARITY: usize = 256 * 1024;

/// Total attempts per request (1 initial try + retries).
const MAX_ATTEMPTS: u32 = 4;
const INITIAL_BACKOFF: Duration = Duration::from_millis(200);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);

/// Characters left unescaped in query parameter values (RFC 3986 unreserved).
const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The object to create.
#[derive(Debug, Clone)]
pub struct NewObject {
    pub name: String,
    pub content_type: String,
    /// Stored as the object's `contentEncoding` (e.g. `gzip`).
    pub content_encoding: Option<String>,
}

/// Somewhere to put objects. Abstracted so the HTTP handler can be tested
/// without GCS.
#[async_trait]
pub trait ObjectStore: Send + Sync {
    fn bucket(&self) -> &str;

    /// Create an object from data that is already in memory.
    async fn put(&self, object: &NewObject, data: Bytes) -> Result<(), StoreError>;

    /// Start an upload whose data is sent in chunks.
    async fn start_upload(&self, object: &NewObject) -> Result<Box<dyn Upload>, StoreError>;
}

/// A chunked upload in progress. Nothing exists in the bucket until `finish`.
#[async_trait]
pub trait Upload: Send {
    /// Append a chunk. Its length must be a multiple of [`CHUNK_GRANULARITY`].
    async fn write(&mut self, data: Bytes) -> Result<(), StoreError>;

    /// Append the last (non-empty) chunk and create the object.
    async fn finish(self: Box<Self>, data: Bytes) -> Result<(), StoreError>;

    /// Abandon the upload. Best effort; GCS also expires unfinished uploads.
    async fn abort(self: Box<Self>);
}

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Response {
    fn describe(&self) -> String {
        format!(
            "GCS returned {}: {}",
            self.status,
            String::from_utf8_lossy(&self.body[..self.body.len().min(512)])
        )
    }

    fn retryable(&self) -> bool {
        matches!(
            self.status,
            StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
        ) || self.status.is_server_error()
    }
}

/// Outcome of one attempt, for [`Inner::retry`].
enum Step<T> {
    Done(T),
    Retry(String),
    Fail(String),
}

struct Inner {
    bucket: String,
    endpoint: String,
    client: HttpsClient,
    /// `None` when talking to an emulator, which needs no credentials.
    tokens: Option<Arc<dyn gcp_auth::TokenProvider>>,
}

impl Inner {
    fn upload_url(&self, upload_type: &str, object: &NewObject) -> String {
        let mut url = format!(
            "{}/upload/storage/v1/b/{}/o?uploadType={upload_type}&ifGenerationMatch=0&name={}",
            self.endpoint,
            utf8_percent_encode(&self.bucket, QUERY_VALUE),
            utf8_percent_encode(&object.name, QUERY_VALUE),
        );
        if let Some(enc) = &object.content_encoding {
            url.push_str("&contentEncoding=");
            url.push_str(&utf8_percent_encode(enc, QUERY_VALUE).to_string());
        }
        url
    }

    /// Send one request. `Err` means no HTTP response (network error,
    /// timeout, or no access token) and is always worth retrying.
    async fn send(
        &self,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Bytes,
        authenticated: bool,
    ) -> Result<Response, String> {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-length", body.len());
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        if authenticated && let Some(tokens) = &self.tokens {
            let token = tokens
                .token(SCOPES)
                .await
                .map_err(|e| format!("failed to get access token: {e}"))?;
            req = req.header("authorization", format!("Bearer {}", token.as_str()));
        }
        let req = req
            .body(Full::new(body))
            .map_err(|e| format!("failed to build request: {e}"))?;

        let send = async {
            let resp = self.client.request(req).await.map_err(|e| e.to_string())?;
            let (parts, body) = resp.into_parts();
            let body = body.collect().await.map_err(|e| e.to_string())?.to_bytes();
            Ok::<_, String>(Response {
                status: parts.status,
                headers: parts.headers,
                body,
            })
        };
        match tokio::time::timeout(ATTEMPT_TIMEOUT, send).await {
            Err(_) => Err(format!("timed out after {ATTEMPT_TIMEOUT:?}")),
            Ok(Err(e)) => Err(format!("request failed: {e}")),
            Ok(Ok(resp)) => Ok(resp),
        }
    }

    /// Run `attempt` (numbered from 1) until it succeeds, fails permanently,
    /// or runs out of attempts.
    async fn retry<T, F, Fut>(&self, object: &str, mut attempt: F) -> Result<T, StoreError>
    where
        F: FnMut(u32) -> Fut,
        Fut: Future<Output = Step<T>>,
    {
        let mut backoff = INITIAL_BACKOFF;
        for n in 1..=MAX_ATTEMPTS {
            match attempt(n).await {
                Step::Done(v) => return Ok(v),
                Step::Fail(msg) => {
                    return Err(StoreError(format!("gs://{}/{object}: {msg}", self.bucket)));
                }
                Step::Retry(msg) if n == MAX_ATTEMPTS => {
                    return Err(StoreError(format!(
                        "gs://{}/{object}: giving up after {MAX_ATTEMPTS} attempts: {msg}",
                        self.bucket
                    )));
                }
                Step::Retry(msg) => {
                    log_retry(object, n, &msg);
                    tokio::time::sleep(with_jitter(backoff)).await;
                    backoff *= 2;
                }
            }
        }
        unreachable!("the loop always returns on the last attempt")
    }
}

fn log_retry(object: &str, attempt: u32, error: &str) {
    crate::log::warning(
        "GCS write failed, retrying",
        serde_json::json!({ "object": object, "attempt": attempt, "error": error }),
    );
}

pub struct GcsStore {
    inner: Arc<Inner>,
}

impl GcsStore {
    /// Create a store for `bucket`.
    ///
    /// If `emulator_host` (from `STORAGE_EMULATOR_HOST`) is set, requests go
    /// there unauthenticated. Otherwise credentials come from Application
    /// Default Credentials: the metadata server on Cloud Run, or
    /// `GOOGLE_APPLICATION_CREDENTIALS` / `gcloud auth application-default
    /// login` locally.
    pub async fn new(bucket: String, emulator_host: Option<String>) -> Result<Self, String> {
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|e| format!("failed to load TLS root certificates: {e}"))?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(60))
            .build(connector);

        let (endpoint, tokens) = match emulator_host.filter(|h| !h.is_empty()) {
            Some(host) => {
                let host = host.trim_end_matches('/');
                let endpoint = if host.contains("://") {
                    host.to_string()
                } else {
                    format!("http://{host}")
                };
                (endpoint, None)
            }
            None => {
                let provider = gcp_auth::provider()
                    .await
                    .map_err(|e| format!("failed to find Google credentials: {e}"))?;
                (GCS_ENDPOINT.to_string(), Some(provider))
            }
        };

        Ok(Self {
            inner: Arc::new(Inner {
                bucket,
                endpoint,
                client,
                tokens,
            }),
        })
    }
}

#[async_trait]
impl ObjectStore for GcsStore {
    fn bucket(&self) -> &str {
        &self.inner.bucket
    }

    async fn put(&self, object: &NewObject, data: Bytes) -> Result<(), StoreError> {
        let inner = &*self.inner;
        let url = inner.upload_url("media", object);
        let headers = [("content-type", object.content_type.as_str())];
        inner
            .retry(&object.name, |attempt| {
                let (url, data) = (&url, data.clone());
                async move {
                    match inner.send(Method::POST, url, &headers, data, true).await {
                        Err(e) => Step::Retry(e),
                        Ok(r) if r.status.is_success() => Step::Done(()),
                        // Object names are unique per request, so a precondition
                        // failure on a retry means an earlier attempt succeeded
                        // but its response was lost.
                        Ok(r) if r.status == StatusCode::PRECONDITION_FAILED && attempt > 1 => {
                            Step::Done(())
                        }
                        Ok(r) if r.retryable() => Step::Retry(r.describe()),
                        Ok(r) => Step::Fail(r.describe()),
                    }
                }
            })
            .await
    }

    async fn start_upload(&self, object: &NewObject) -> Result<Box<dyn Upload>, StoreError> {
        let inner = &*self.inner;
        let url = inner.upload_url("resumable", object);
        let headers = [("x-upload-content-type", object.content_type.as_str())];
        let session = inner
            .retry(&object.name, |_| {
                let url = &url;
                async move {
                    match inner
                        .send(Method::POST, url, &headers, Bytes::new(), true)
                        .await
                    {
                        Err(e) => Step::Retry(e),
                        Ok(r) if r.status.is_success() => {
                            match r.headers.get("location").and_then(|v| v.to_str().ok()) {
                                Some(loc) => Step::Done(loc.to_string()),
                                None => Step::Fail("resumable upload has no Location".into()),
                            }
                        }
                        Ok(r) if r.retryable() => Step::Retry(r.describe()),
                        Ok(r) => Step::Fail(r.describe()),
                    }
                }
            })
            .await?;
        Ok(Box::new(GcsUpload {
            inner: self.inner.clone(),
            session,
            name: object.name.clone(),
            offset: 0,
        }))
    }
}

/// A GCS resumable upload session.
/// <https://cloud.google.com/storage/docs/performing-resumable-uploads>
struct GcsUpload {
    inner: Arc<Inner>,
    /// The session URI. It is itself the credential, so requests to it are
    /// sent without an access token.
    session: String,
    name: String,
    /// Bytes GCS has confirmed it persisted.
    offset: u64,
}

enum SessionStatus {
    Complete,
    Persisted(u64),
}

impl GcsUpload {
    fn error(&self, msg: impl std::fmt::Display) -> StoreError {
        StoreError(format!("gs://{}/{}: {msg}", self.inner.bucket, self.name))
    }

    /// Drop the bytes GCS says it has persisted from the front of `data`.
    fn advance(&mut self, data: &mut Bytes, persisted: u64) -> Result<(), StoreError> {
        if persisted < self.offset || persisted - self.offset > data.len() as u64 {
            return Err(self.error(format!(
                "GCS reported {persisted} bytes persisted, expected {}..={}",
                self.offset,
                self.offset + data.len() as u64
            )));
        }
        data.advance((persisted - self.offset) as usize);
        self.offset = persisted;
        Ok(())
    }

    async fn status(&self) -> Result<SessionStatus, String> {
        let r = self
            .inner
            .send(
                Method::PUT,
                &self.session,
                &[("content-range", "bytes */*")],
                Bytes::new(),
                false,
            )
            .await?;
        match r.status {
            s if s.is_success() => Ok(SessionStatus::Complete),
            StatusCode::PERMANENT_REDIRECT => Ok(SessionStatus::Persisted(persisted(&r.headers))),
            _ => Err(r.describe()),
        }
    }

    /// Send `data` at the current offset; with `last`, also finalize.
    async fn send_range(&mut self, mut data: Bytes, last: bool) -> Result<(), StoreError> {
        let total = last.then(|| (self.offset + data.len() as u64).to_string());
        let total = total.as_deref().unwrap_or("*");
        let mut failures = 0;
        let mut backoff = INITIAL_BACKOFF;
        loop {
            let range = if data.is_empty() {
                format!("bytes */{total}")
            } else {
                let end = self.offset + data.len() as u64 - 1;
                format!("bytes {}-{end}/{total}", self.offset)
            };
            let result = self
                .inner
                .send(
                    Method::PUT,
                    &self.session,
                    &[("content-range", &range)],
                    data.clone(),
                    false,
                )
                .await;
            let error = match result {
                Ok(r) if r.status.is_success() => {
                    return if last {
                        Ok(())
                    } else {
                        Err(self.error("GCS finalized the upload before the last chunk"))
                    };
                }
                Ok(r) if r.status == StatusCode::PERMANENT_REDIRECT => {
                    // 308: GCS kept some or all of the chunk.
                    let before = self.offset;
                    self.advance(&mut data, persisted(&r.headers))?;
                    if data.is_empty() && !last {
                        return Ok(());
                    }
                    if self.offset > before {
                        continue; // Send whatever GCS did not keep.
                    }
                    format!("GCS persisted nothing ({} bytes so far)", self.offset)
                }
                Ok(r) if r.status == StatusCode::PRECONDITION_FAILED && last && failures > 0 => {
                    // An earlier attempt created the object but its response
                    // was lost.
                    return Ok(());
                }
                Ok(r) if r.retryable() => r.describe(),
                Ok(r) => return Err(self.error(r.describe())),
                Err(e) => e,
            };

            failures += 1;
            if failures >= MAX_ATTEMPTS {
                return Err(self.error(format!("giving up after {MAX_ATTEMPTS} attempts: {error}")));
            }
            log_retry(&self.name, failures, &error);
            tokio::time::sleep(with_jitter(backoff)).await;
            backoff *= 2;

            // The failed request may still have been partly persisted; ask
            // GCS where to resume from. If that fails too, resend as-is.
            match self.status().await {
                Ok(SessionStatus::Complete) if last => return Ok(()),
                Ok(SessionStatus::Complete) => {
                    return Err(self.error("GCS finalized the upload before the last chunk"));
                }
                Ok(SessionStatus::Persisted(n)) => self.advance(&mut data, n)?,
                Err(_) => {}
            }
        }
    }
}

/// Bytes persisted according to a 308 response's `Range: bytes=0-N` header.
fn persisted(headers: &HeaderMap) -> u64 {
    headers
        .get("range")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("bytes=0-"))
        .and_then(|end| end.parse::<u64>().ok())
        .map_or(0, |end| end + 1)
}

#[async_trait]
impl Upload for GcsUpload {
    async fn write(&mut self, data: Bytes) -> Result<(), StoreError> {
        debug_assert!(!data.is_empty() && data.len().is_multiple_of(CHUNK_GRANULARITY));
        self.send_range(data, false).await
    }

    async fn finish(mut self: Box<Self>, data: Bytes) -> Result<(), StoreError> {
        self.send_range(data, true).await
    }

    async fn abort(self: Box<Self>) {
        // GCS answers a cancelled session with 499.
        let _ = self
            .inner
            .send(Method::DELETE, &self.session, &[], Bytes::new(), false)
            .await;
    }
}

/// Add up to 50% random jitter so retries from concurrent requests spread out.
fn with_jitter(d: Duration) -> Duration {
    // The low 64 bits of a v7 UUID are random.
    let random = uuid::Uuid::now_v7().as_u128() as u64;
    let max_extra = (d.as_millis() as u64 / 2).max(1);
    d + Duration::from_millis(random % max_extra)
}

/// In-memory store for tests.
#[cfg(test)]
pub mod memory {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Clone)]
    pub struct StoredObject {
        pub name: String,
        pub content_type: String,
        pub content_encoding: Option<String>,
        pub data: Bytes,
    }

    #[derive(Default, Clone)]
    pub struct MemoryStore {
        pub objects: Arc<Mutex<Vec<StoredObject>>>,
        /// Sizes of every chunk passed to `Upload::write` / `finish`.
        pub chunks: Arc<Mutex<Vec<usize>>>,
        pub aborted: Arc<AtomicUsize>,
        /// Fail every write to an object whose name ends with this suffix.
        pub fail_suffix: Option<&'static str>,
    }

    impl MemoryStore {
        pub fn objects(&self) -> Vec<StoredObject> {
            self.objects.lock().unwrap().clone()
        }

        pub fn chunks(&self) -> Vec<usize> {
            self.chunks.lock().unwrap().clone()
        }

        pub fn aborted(&self) -> usize {
            self.aborted.load(Ordering::SeqCst)
        }

        fn check(&self, name: &str) -> Result<(), StoreError> {
            match self.fail_suffix {
                Some(s) if name.ends_with(s) => Err(StoreError("injected failure".into())),
                _ => Ok(()),
            }
        }
    }

    #[async_trait]
    impl ObjectStore for MemoryStore {
        fn bucket(&self) -> &str {
            "test-bucket"
        }

        async fn put(&self, object: &NewObject, data: Bytes) -> Result<(), StoreError> {
            self.check(&object.name)?;
            self.objects.lock().unwrap().push(StoredObject {
                name: object.name.clone(),
                content_type: object.content_type.clone(),
                content_encoding: object.content_encoding.clone(),
                data,
            });
            Ok(())
        }

        async fn start_upload(&self, object: &NewObject) -> Result<Box<dyn Upload>, StoreError> {
            self.check(&object.name)?;
            Ok(Box::new(MemoryUpload {
                store: self.clone(),
                object: object.clone(),
                data: Vec::new(),
            }))
        }
    }

    struct MemoryUpload {
        store: MemoryStore,
        object: NewObject,
        data: Vec<u8>,
    }

    #[async_trait]
    impl Upload for MemoryUpload {
        async fn write(&mut self, data: Bytes) -> Result<(), StoreError> {
            self.store.chunks.lock().unwrap().push(data.len());
            self.data.extend_from_slice(&data);
            Ok(())
        }

        async fn finish(mut self: Box<Self>, data: Bytes) -> Result<(), StoreError> {
            self.store.chunks.lock().unwrap().push(data.len());
            self.data.extend_from_slice(&data);
            let all = Bytes::from(std::mem::take(&mut self.data));
            self.store.put(&self.object, all).await
        }

        async fn abort(self: Box<Self>) {
            self.store.aborted.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Query, RawQuery, State};
    use axum::http::HeaderMap as AxumHeaders;
    use axum::response::{IntoResponse, Response as AxumResponse};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn object(name: &str) -> NewObject {
        NewObject {
            name: name.into(),
            content_type: "application/json".into(),
            content_encoding: None,
        }
    }

    #[tokio::test]
    async fn emulator_endpoint_is_normalised() {
        for (host, expected) in [
            ("localhost:4443", "http://localhost:4443"),
            ("http://gcs:4443/", "http://gcs:4443"),
            ("https://gcs.example", "https://gcs.example"),
        ] {
            let store = GcsStore::new("b".into(), Some(host.into())).await.unwrap();
            assert_eq!(store.inner.endpoint, expected);
            assert!(store.inner.tokens.is_none());
        }
    }

    #[tokio::test]
    async fn upload_url_escapes_object_name() {
        let store = GcsStore::new("my-bucket".into(), Some("localhost:1".into()))
            .await
            .unwrap();
        assert_eq!(
            store
                .inner
                .upload_url("media", &object("a/b c/ts=1/x+y.json")),
            "http://localhost:1/upload/storage/v1/b/my-bucket/o?uploadType=media\
             &ifGenerationMatch=0&name=a%2Fb%20c%2Fts%3D1%2Fx%2By.json"
        );
        let gzipped = NewObject {
            content_encoding: Some("gzip".into()),
            ..object("o")
        };
        assert!(
            store
                .inner
                .upload_url("resumable", &gzipped)
                .ends_with("uploadType=resumable&ifGenerationMatch=0&name=o&contentEncoding=gzip")
        );
    }

    #[test]
    fn jitter_stays_in_range() {
        for _ in 0..100 {
            let d = with_jitter(Duration::from_millis(200));
            assert!(d >= Duration::from_millis(200) && d < Duration::from_millis(300));
        }
    }

    #[test]
    fn persisted_parses_range_header() {
        let mut h = HeaderMap::new();
        assert_eq!(persisted(&h), 0);
        h.insert("range", "bytes=0-262143".parse().unwrap());
        assert_eq!(persisted(&h), 262144);
    }

    /// A small fake of the GCS upload API with fault injection.
    #[derive(Default)]
    struct MockGcs {
        base: Mutex<String>,
        /// Simple-upload objects and finalized resumable uploads.
        objects: Mutex<HashMap<String, (String, Vec<u8>)>>,
        session_object: Mutex<Option<(String, String)>>,
        session_data: Mutex<Vec<u8>>,
        init_queries: Mutex<Vec<String>>,
        /// Answer this many requests with 503 without persisting anything.
        fail_next: AtomicUsize,
        /// Persist the next chunk, then answer 503 anyway (lost response).
        persist_then_fail: AtomicBool,
        /// Persist only half of the next chunk and say so with a 308.
        persist_half: AtomicBool,
        deleted: AtomicBool,
        puts: AtomicUsize,
    }

    type Mock = Arc<MockGcs>;

    async fn mock_upload(
        State(m): State<Mock>,
        RawQuery(raw): RawQuery,
        Query(q): Query<HashMap<String, String>>,
        headers: AxumHeaders,
        body: Bytes,
    ) -> AxumResponse {
        if m.fail_next.load(Ordering::SeqCst) > 0 {
            m.fail_next.fetch_sub(1, Ordering::SeqCst);
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let name = q["name"].clone();
        match q["uploadType"].as_str() {
            "media" => {
                let mut objects = m.objects.lock().unwrap();
                if objects.contains_key(&name) {
                    return StatusCode::PRECONDITION_FAILED.into_response();
                }
                let ct = headers["content-type"].to_str().unwrap().to_string();
                objects.insert(name, (ct, body.to_vec()));
                StatusCode::OK.into_response()
            }
            _ => {
                m.init_queries.lock().unwrap().push(raw.unwrap_or_default());
                let ct = headers["x-upload-content-type"]
                    .to_str()
                    .unwrap()
                    .to_string();
                *m.session_object.lock().unwrap() = Some((name, ct));
                let location = format!("{}/session", m.base.lock().unwrap());
                (StatusCode::OK, [("location", location)]).into_response()
            }
        }
    }

    fn incomplete(len: usize) -> AxumResponse {
        if len == 0 {
            StatusCode::PERMANENT_REDIRECT.into_response()
        } else {
            let range = format!("bytes=0-{}", len - 1);
            (StatusCode::PERMANENT_REDIRECT, [("range", range)]).into_response()
        }
    }

    async fn mock_session(
        State(m): State<Mock>,
        headers: AxumHeaders,
        body: Bytes,
    ) -> AxumResponse {
        m.puts.fetch_add(1, Ordering::SeqCst);
        if m.fail_next.load(Ordering::SeqCst) > 0 {
            m.fail_next.fetch_sub(1, Ordering::SeqCst);
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let range = headers["content-range"].to_str().unwrap().to_string();
        let (span, total) = range
            .strip_prefix("bytes ")
            .unwrap()
            .split_once('/')
            .unwrap();
        let mut data = m.session_data.lock().unwrap();

        let finalize = |data: &Vec<u8>| {
            let (name, ct) = m.session_object.lock().unwrap().clone().unwrap();
            m.objects.lock().unwrap().insert(name, (ct, data.clone()));
            StatusCode::OK.into_response()
        };

        if span == "*" {
            // Status query, or finalize with no new data.
            if total != "*" && total.parse::<usize>().unwrap() == data.len() {
                return finalize(&data);
            }
            let (name, _) = m.session_object.lock().unwrap().clone().unwrap();
            if m.objects.lock().unwrap().contains_key(&name) {
                return StatusCode::OK.into_response();
            }
            return incomplete(data.len());
        }

        let start: usize = span.split_once('-').unwrap().0.parse().unwrap();
        // Real GCS requires each chunk to start where the last one ended.
        if start != data.len() {
            return (
                StatusCode::BAD_REQUEST,
                format!("expected offset {}", data.len()),
            )
                .into_response();
        }
        if m.persist_half.swap(false, Ordering::SeqCst) {
            data.extend_from_slice(&body[..body.len() / 2]);
            return incomplete(data.len());
        }
        data.extend_from_slice(&body);
        if m.persist_then_fail.swap(false, Ordering::SeqCst) {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        if total != "*" && total.parse::<usize>().unwrap() == data.len() {
            return finalize(&data);
        }
        incomplete(data.len())
    }

    async fn mock_delete(State(m): State<Mock>) -> StatusCode {
        m.deleted.store(true, Ordering::SeqCst);
        StatusCode::from_u16(499).unwrap()
    }

    async fn mock() -> (Mock, GcsStore) {
        use axum::routing::{post, put};
        let m: Mock = Arc::default();
        let app = axum::Router::new()
            .route("/upload/storage/v1/b/{bucket}/o", post(mock_upload))
            .route("/session", put(mock_session).delete(mock_delete))
            .with_state(m.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        *m.base.lock().unwrap() = base.clone();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let store = GcsStore::new("bucket".into(), Some(base)).await.unwrap();
        (m, store)
    }

    fn pattern(len: usize) -> Bytes {
        (0..len)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<u8>>()
            .into()
    }

    async fn stream(store: &GcsStore, data: &Bytes, chunk: usize) -> Result<(), StoreError> {
        let mut upload = store.start_upload(&object("big.bin")).await?;
        let mut rest = data.clone();
        while rest.len() > chunk {
            upload.write(rest.split_to(chunk)).await?;
        }
        upload.finish(rest).await
    }

    fn stored(m: &MockGcs, name: &str) -> Option<Vec<u8>> {
        m.objects.lock().unwrap().get(name).map(|(_, d)| d.clone())
    }

    #[tokio::test]
    async fn put_retries_transient_errors() {
        let (m, store) = mock().await;
        m.fail_next.store(2, Ordering::SeqCst);
        store.put(&object("o"), Bytes::from("hi")).await.unwrap();
        assert_eq!(stored(&m, "o").unwrap(), b"hi");
    }

    #[tokio::test]
    async fn put_gives_up_eventually() {
        let (m, store) = mock().await;
        m.fail_next.store(MAX_ATTEMPTS as usize, Ordering::SeqCst);
        let err = store
            .put(&object("o"), Bytes::from("hi"))
            .await
            .unwrap_err();
        assert!(err.0.contains("giving up"), "{err}");
    }

    #[tokio::test]
    async fn resumable_upload_streams_chunks() {
        let (m, store) = mock().await;
        let data = pattern(3 * CHUNK_GRANULARITY + 123);
        stream(&store, &data, CHUNK_GRANULARITY).await.unwrap();
        assert_eq!(stored(&m, "big.bin").unwrap(), data);
        assert_eq!(m.puts.load(Ordering::SeqCst), 4);
        let (_, ct) = m.session_object.lock().unwrap().clone().unwrap();
        assert_eq!(ct, "application/json");
    }

    #[tokio::test]
    async fn resumable_upload_retries_a_failed_chunk() {
        let (m, store) = mock().await;
        let data = pattern(2 * CHUNK_GRANULARITY + 5);
        let mut upload = store.start_upload(&object("big.bin")).await.unwrap();
        upload.write(data.slice(..CHUNK_GRANULARITY)).await.unwrap();
        m.fail_next.store(2, Ordering::SeqCst); // chunk 2 fails, then the status query
        upload
            .write(data.slice(CHUNK_GRANULARITY..2 * CHUNK_GRANULARITY))
            .await
            .unwrap();
        upload
            .finish(data.slice(2 * CHUNK_GRANULARITY..))
            .await
            .unwrap();
        assert_eq!(stored(&m, "big.bin").unwrap(), data);
    }

    #[tokio::test]
    async fn resumable_upload_resumes_after_lost_response() {
        // GCS stored the chunk but the response never arrived: the client must
        // ask where to resume and not resend (which real GCS would reject).
        let (m, store) = mock().await;
        let data = pattern(2 * CHUNK_GRANULARITY + 5);
        m.persist_then_fail.store(true, Ordering::SeqCst);
        stream(&store, &data, CHUNK_GRANULARITY).await.unwrap();
        assert_eq!(stored(&m, "big.bin").unwrap(), data);
    }

    #[tokio::test]
    async fn resumable_upload_completes_after_lost_final_response() {
        let (m, store) = mock().await;
        let data = pattern(CHUNK_GRANULARITY + 5);
        let mut upload = store.start_upload(&object("big.bin")).await.unwrap();
        upload.write(data.slice(..CHUNK_GRANULARITY)).await.unwrap();
        m.persist_then_fail.store(true, Ordering::SeqCst);
        upload
            .finish(data.slice(CHUNK_GRANULARITY..))
            .await
            .unwrap();
        assert_eq!(stored(&m, "big.bin").unwrap(), data);
    }

    #[tokio::test]
    async fn resumable_upload_resends_partially_persisted_chunk() {
        let (m, store) = mock().await;
        let data = pattern(2 * CHUNK_GRANULARITY + 5);
        m.persist_half.store(true, Ordering::SeqCst);
        stream(&store, &data, 2 * CHUNK_GRANULARITY).await.unwrap();
        assert_eq!(stored(&m, "big.bin").unwrap(), data);
    }

    #[tokio::test]
    async fn resumable_upload_passes_content_encoding() {
        let (m, store) = mock().await;
        let obj = NewObject {
            content_encoding: Some("gzip".into()),
            ..object("o")
        };
        store.start_upload(&obj).await.unwrap();
        assert!(m.init_queries.lock().unwrap()[0].ends_with("&contentEncoding=gzip"));
    }

    #[tokio::test]
    async fn abort_cancels_the_session() {
        let (m, store) = mock().await;
        let mut upload = store.start_upload(&object("big.bin")).await.unwrap();
        upload.write(pattern(CHUNK_GRANULARITY)).await.unwrap();
        upload.abort().await;
        assert!(m.deleted.load(Ordering::SeqCst));
        assert!(stored(&m, "big.bin").is_none());
    }
}
