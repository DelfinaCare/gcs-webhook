# gcs-webhook

A minimal webhook receiver that writes each request body, plus a metadata file
describing the request, to a [Google Cloud Storage](https://cloud.google.com/storage)
bucket. Designed to run on [Cloud Run](https://cloud.google.com/run) and
configured entirely through environment variables.

## Design Goals

- **Durable before acknowledged.** The `200 OK` is sent only after the body *and* the
  metadata file have both been written to GCS. If either write fails, the
  sender gets a `503` and can retry.
- **Minimal attack surface.** Written in Rust and deployed in a `scratch` Docker
  container with no OS or shell. It runs as an unprivileged user and needs only
  `roles/storage.objectCreator`.
- **Streaming.** Large bodies are streamed to GCS in chunks, so memory use
  stays flat however large the request is (see
  [Supporting large uploads](#supporting-large-uploads)).
- **Simple.** One binary, configured by a handful of environment variables.

## How it works

For every accepted request:

1. The request is authenticated against the raw body bytes (see [Authentication](#authentication)).
2. The body is written byte-for-byte, with its original `Content-Type` and
   `Content-Encoding`, to `<base>.<ext>`.
3. A JSON metadata file is written to `<base>.meta.json`, right next to the body.
4. The service responds `200 OK` with `{"id": "<uuid>"}`.

The body is always written before the metadata, so **if a `.meta.json` exists,
its body is complete**. A body without a `.meta.json` is left over from a
delivery that failed partway (the sender was told to retry), and can be ignored.
This also makes `.meta.json` a good object-finalize trigger for downstream
processing.

Uploads use `ifGenerationMatch=0`, so existing objects are never overwritten.

### Large bodies and streaming

Bodies up to `UPLOAD_CHUNK_BYTES` (8 MiB) are held in memory and written with a
single request. Larger bodies are streamed into a GCS
[resumable upload](https://cloud.google.com/storage/docs/resumable-uploads):
each full chunk is sent as soon as it arrives, so a process only ever holds
about one chunk per in-flight request. (A 99 MiB upload peaks at about 18 MiB of
memory.)

Signatures can only be checked once the whole body has arrived, so the **last
chunk is held back** until authentication passes. A resumable upload creates
its object only when the last chunk is sent, so if the signature is wrong the
upload is cancelled and nothing ever appears in the bucket. Header-secret auth
(`AUTH_MODE=header`) is checked before any of the body is read.

Bodies are never decoded. A `Content-Encoding: gzip` body is stored compressed,
exactly as sent, with the object's `contentEncoding` set to `gzip`. Signatures
are checked against the compressed bytes, which is what senders sign. GCS then
[transcodes](https://cloud.google.com/storage/docs/transcoding) on download:
clients that send `Accept-Encoding: gzip` get the stored bytes, and others get
them decompressed.

### Object names

`<base>` comes from `OBJECT_PATH_TEMPLATE`, which defaults to
`{path}/dt={date}/{timestamp}_{id}`. For example, a JSON POST to
`/webhook_acme/orders?x=1` produces:

```
gs://BUCKET/webhook_acme/orders/dt=2026-11-08/20261108T222327.097388743Z_01a1bd42-6379-7789-bac2-eda34ba1e642.json
gs://BUCKET/webhook_acme/orders/dt=2026-11-08/20261108T222327.097388743Z_01a1bd42-6379-7789-bac2-eda34ba1e642.meta.json
```

| Placeholder    | Example                         | Notes                                          |
|----------------|---------------------------------|------------------------------------------------|
| `{path}`       | `webhook_acme/orders`           | Request path, sanitized (see below); `/` → `root` |
| `{id}`         | `01a1bd42-6379-7789-…`          | UUIDv7 (time-ordered). **Required.**           |
| `{timestamp}`  | `20261108T222327.097388743Z`    | UTC, sorts lexicographically                   |
| `{unix_nanos}` | `1794176607097388743`           |                                                |
| `{date}`       | `2026-11-08`                    | UTC                                            |
| `{year}` `{month}` `{day}` `{hour}` | `2026` `11` `08` `22` | UTC, zero-padded                  |

The query string is never part of the path. Empty, `.` and `..` segments are
dropped, and characters outside `A-Z a-z 0-9 . _ ~ % = + , @ : -` are replaced
with `_`. Literal text works too, e.g. `raw/{path}/{year}/{month}/{day}/{id}`.

The body extension comes from `Content-Type`: `.json` (`application/json`,
`*+json`), `.jsonl`, `.xml`, `.form` (`application/x-www-form-urlencoded`),
`.txt`, `.csv`, or `.bin` for anything else.

### Metadata file

```json
{
  "id": "01a1bd42-6379-7789-bac2-eda34ba1e642",
  "received_at": "2026-11-08T22:23:27.097388743Z",
  "received_at_unix_nanos": 1794176607097388743,
  "method": "POST",
  "path": "/webhook_acme/orders",
  "query": "source=it",
  "remote_addr": "169.254.1.1:49242",
  "auth_mode": "header",
  "headers": {
    "acme-webhook-secret": ["[REDACTED]"],
    "content-type": ["application/json"],
    "x-delivery-id": ["delivery-1"],
    "x-forwarded-for": ["203.0.113.7"]
  },
  "body": {
    "bucket": "BUCKET",
    "object": "webhook_acme/orders/dt=2026-11-08/20261108T222327.097388743Z_01a1bd42-….json",
    "uri": "gs://BUCKET/webhook_acme/orders/dt=2026-11-08/20261108T222327.097388743Z_01a1bd42-….json",
    "content_type": "application/json",
    "content_encoding": null,
    "size": 43,
    "sha256": "912bf07f122bf04b06ff332150d29f20d0a9a010c5fc64c04eaa5052ffd0cf58"
  },
  "receiver": { "name": "gcs-webhook", "version": "0.1.0" }
}
```

Every header value is an array, because headers can repeat. On Cloud Run,
`remote_addr` is Google's front end; the real client is in `x-forwarded-for`.
Header values listed in `REDACT_HEADERS` are replaced with `[REDACTED]`, and in
`header` auth mode the secret header is always redacted. HMAC signature headers
are kept, since they are not secrets and let you re-verify a delivery later.

Senders retry, so the same event can be stored more than once. Deduplicate
downstream using the provider's delivery ID header (e.g. `x-github-delivery`,
`webhook-id`), which is in `headers`.

## Endpoints

| Method              | Path                       | Description                          |
|---------------------|----------------------------|--------------------------------------|
| `ALLOWED_METHODS`   | `WEBHOOK_PATH_PREFIX` and below | Receives webhooks               |
| GET                 | `/health`                  | Health check (returns `200 OK`)      |

| Status | Meaning                                                            |
|--------|--------------------------------------------------------------------|
| 200    | Body and metadata written. Response body is `{"id": "..."}`        |
| 401    | Authentication failed (the reason is logged, not returned)         |
| 404    | Path is outside `WEBHOOK_PATH_PREFIX`                              |
| 405    | Method not in `ALLOWED_METHODS`                                    |
| 413    | Body larger than `MAX_BODY_BYTES`                                  |
| 503    | GCS write failed after retries; the sender should retry            |

## Configuration

| Variable                | Default                                 | Description |
|-------------------------|-----------------------------------------|-------------|
| `GCS_BUCKET`            | **required**                            | Bucket name (`my-bucket` or `gs://my-bucket`) |
| `AUTH_MODE`             | **required**                            | `none`, `header`, `hmac`, `standard-webhooks` or `stripe` |
| `AUTH_SECRET`           |                                         | Shared secret / signing key (all modes except `none`) |
| `AUTH_HEADER`           |                                         | Header carrying the secret (`header`) or signature (`hmac`) |
| `AUTH_HMAC_ALGORITHM`   | `sha256`                                | `sha1`, `sha256` or `sha512` |
| `AUTH_HMAC_ENCODING`    | `hex`                                   | `hex` or `base64` |
| `AUTH_HMAC_PREFIX`      |                                         | Stripped from the signature before decoding, e.g. `sha256=` |
| `AUTH_HMAC_TIMESTAMP_HEADER` |                                    | Header with a unix-seconds timestamp to sign and check |
| `AUTH_HMAC_PAYLOAD`     | `{body}`                                | What is signed, e.g. `v0:{timestamp}:{body}` |
| `AUTH_TIMESTAMP_TOLERANCE_SECS` | `300`                           | Maximum clock skew for timestamped schemes (replay protection) |
| `WEBHOOK_PATH_PREFIX`   | `/`                                     | Only accept paths at or below this prefix |
| `ALLOWED_METHODS`       | `POST`                                  | Comma-separated, e.g. `POST,PUT` |
| `OBJECT_PATH_TEMPLATE`  | `{path}/dt={date}/{timestamp}_{id}`     | See [Object names](#object-names) |
| `MAX_BODY_BYTES`        | `10485760` (10 MiB)                     | Larger bodies get `413`. Read [Supporting large uploads](#supporting-large-uploads) before raising it |
| `UPLOAD_CHUNK_BYTES`    | `8388608` (8 MiB)                       | Bodies larger than this are streamed in chunks of this size. Must be a multiple of 256 KiB |
| `REDACT_HEADERS`        | `authorization,proxy-authorization,cookie` | Header values replaced with `[REDACTED]` in metadata |
| `PORT`                  | `8080`                                  | Port to listen on (set by Cloud Run) |
| `STORAGE_EMULATOR_HOST` |                                         | Use a GCS emulator, unauthenticated (for local dev and tests) |

Configuration is checked at startup, and the process exits with an error log on
the first problem. Empty values are treated as unset.

GCS credentials come from
[Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials):
the service account on Cloud Run, or `GOOGLE_APPLICATION_CREDENTIALS` /
`gcloud auth application-default login` locally. Failed writes (timeouts,
`429`, `5xx`) are retried up to 4 times with jittered exponential backoff,
each attempt with a 60 s timeout. A failed chunk of a streamed upload resumes
from wherever GCS says it got to.

## Authentication

All signatures are checked against the exact bytes received, using constant-time
comparisons. `AUTH_MODE` must be set explicitly; there is no default, so the
service never runs open by accident.

### `header`: shared secret in a header

```bash
AUTH_MODE=header
AUTH_HEADER=Acme-Webhook-Secret
AUTH_SECRET=...            # from Secret Manager
```

For a bearer token, use `AUTH_HEADER=Authorization` and `AUTH_SECRET="Bearer <token>"`.
For HTTP basic auth, use `AUTH_SECRET="Basic <base64 user:pass>"`.

### `hmac`: HMAC signature in a header

Covers most providers that sign the body. Some common setups:

| Provider | Settings |
|----------|----------|
| GitHub   | `AUTH_HEADER=X-Hub-Signature-256` `AUTH_HMAC_PREFIX=sha256=` |
| Shopify  | `AUTH_HEADER=X-Shopify-Hmac-Sha256` `AUTH_HMAC_ENCODING=base64` |
| Slack    | `AUTH_HEADER=X-Slack-Signature` `AUTH_HMAC_PREFIX=v0=` `AUTH_HMAC_TIMESTAMP_HEADER=X-Slack-Request-Timestamp` `AUTH_HMAC_PAYLOAD=v0:{timestamp}:{body}` |

`AUTH_HMAC_PAYLOAD` must contain `{body}` exactly once. If `AUTH_HMAC_TIMESTAMP_HEADER`
is set, the payload must also contain `{timestamp}`, and requests whose timestamp
is more than `AUTH_TIMESTAMP_TOLERANCE_SECS` from now are rejected.

### `standard-webhooks`

The [Standard Webhooks](https://www.standardwebhooks.com/) spec, also used by Svix
and the many providers built on it. Set `AUTH_SECRET` to the `whsec_...` signing
secret. Both `webhook-*` and `svix-*` header names are accepted.

### `stripe`

Verifies the `Stripe-Signature` header. Set `AUTH_SECRET` to the endpoint's `whsec_...`
signing secret.

### `none`

No application-level check. Use this only when something else authenticates
requests, e.g. Cloud Run IAM (`--no-allow-unauthenticated`) for internal senders
that can attach a Google ID token.

## Usage

### Run Locally

Against the [fake-gcs-server](https://github.com/fsouza/fake-gcs-server) emulator:

```bash
docker run -d --name gcs -p 4443:4443 fsouza/fake-gcs-server -scheme http -backend memory
curl -X POST "http://localhost:4443/storage/v1/b?project=dev" -d '{"name":"webhooks"}'

GCS_BUCKET=webhooks STORAGE_EMULATOR_HOST=localhost:4443 \
AUTH_MODE=header AUTH_HEADER=X-Secret AUTH_SECRET=dev \
cargo run

curl -X POST localhost:8080/test -H 'X-Secret: dev' -H 'Content-Type: application/json' -d '{"hello":"world"}'
curl -s localhost:4443/storage/v1/b/webhooks/o | jq '.items[].name'
```

### Docker

```bash
docker build -t gcs-webhook .
docker run -p 8080:8080 -e GCS_BUCKET=... -e AUTH_MODE=... gcs-webhook
```

### Deploy to Cloud Run

```bash
PROJECT=my-project
REGION=us-central1
BUCKET=my-webhook-bucket
SA=gcs-webhook@$PROJECT.iam.gserviceaccount.com

# Service account that may only create objects in the bucket
gcloud iam service-accounts create gcs-webhook --project $PROJECT
gcloud storage buckets add-iam-policy-binding gs://$BUCKET \
  --member serviceAccount:$SA --role roles/storage.objectCreator

# Webhook secret in Secret Manager
printf '%s' "$ACME_API_KEY" | gcloud secrets create acme-webhook-secret --data-file=- --project $PROJECT
gcloud secrets add-iam-policy-binding acme-webhook-secret --project $PROJECT \
  --member serviceAccount:$SA --role roles/secretmanager.secretAccessor

# Cloud Run can only pull from Artifact Registry (or Docker Hub), so mirror the
# ghcr.io image first, e.g. with an Artifact Registry remote repository.
gcloud run deploy gcs-webhook-acme \
  --project $PROJECT --region $REGION \
  --image us-docker.pkg.dev/$PROJECT/REPO/gcs-webhook:0.1 \
  --service-account $SA \
  --allow-unauthenticated \
  --set-env-vars GCS_BUCKET=$BUCKET,WEBHOOK_PATH_PREFIX=/webhook_acme/,AUTH_MODE=header,AUTH_HEADER=Acme-Webhook-Secret \
  --set-secrets AUTH_SECRET=acme-webhook-secret:latest
```

Each service has a single auth configuration, so run one Cloud Run service per
sender. Services scale to zero, so idle ones cost nothing.

The service has no rate limiting of its own. Before exposing it with
`--allow-unauthenticated`, see
[Protecting the endpoint with Cloud Armor](#protecting-the-endpoint-with-cloud-armor).

## Supporting large uploads

`MAX_BODY_BYTES` defaults to 10 MiB. Raising it is safe for memory, since large
bodies are [streamed](#large-bodies-and-streaming), but it raises the cost of
abuse:

- With **signature-based auth** (`hmac`, `stripe`, `standard-webhooks`), the
  signature can only be checked after the whole body has arrived. Anyone who
  knows the URL can send `MAX_BODY_BYTES` with a made-up signature, and the
  service has to receive all of it (and stream most of it into a GCS upload that
  is then cancelled) before rejecting it with `401`.
- With **header-secret auth** (`AUTH_MODE=header`), requests without the right
  secret are rejected before any of the body is read, so the body size limit
  matters much less.

So only raise the limit for senders that need it, and put the protections below
in front of the service first.

### HTTP/2 for bodies over 32 MiB

Cloud Run rejects HTTP/1 requests larger than
[32 MiB](https://cloud.google.com/run/quotas), whatever `MAX_BODY_BYTES` says.
Deploy with end-to-end HTTP/2 to remove that limit:

```bash
gcloud run services update gcs-webhook-acme --use-http2 \
  --update-env-vars MAX_BODY_BYTES=104857600
```

With `--use-http2`, Google's front end forwards every request to the container
as HTTP/2 cleartext (h2c), and this server accepts both h2c and HTTP/1, so
switching is safe. Senders don't change anything: they still connect over HTTPS
with HTTP/1.1 or HTTP/2, and this works the same
[behind a load balancer](https://cloud.google.com/run/docs/configuring/http2).
To check h2c locally: `curl --http2-prior-knowledge http://localhost:8080/health`.

### Memory and timeouts

- **Memory:** each in-flight request holds at most about one chunk
  (`UPLOAD_CHUNK_BYTES`, 8 MiB by default). Size the instance for
  `concurrency × chunk` plus about 20 MiB. For example, the default 512 MiB
  with `--concurrency 40` is comfortable. Lowering `UPLOAD_CHUNK_BYTES` (in
  multiples of 256 KiB) trades memory for more requests to GCS.
- **Timeouts:** a large body from a slow sender can take a while. Cloud Run's
  default request timeout is 5 minutes. Raise it with `--timeout` if needed.

### Protecting the endpoint with Cloud Armor

The service has no rate limiting of its own. To limit abuse, put a global
external Application Load Balancer in front of the Cloud Run service (with a
[serverless NEG](https://cloud.google.com/load-balancing/docs/https/setup-global-ext-https-serverless))
and attach a [Cloud Armor](https://cloud.google.com/armor/docs/cloud-armor-overview)
security policy. Restrict ingress so the `run.app` URL can't be used to bypass
the load balancer, then create the policy and attach it:

```bash
gcloud run services update gcs-webhook-acme --ingress internal-and-cloud-load-balancing

gcloud compute security-policies create gcs-webhook-policy
gcloud compute backend-services update gcs-webhook-backend --global \
  --security-policy gcs-webhook-policy
```

**Banning IPs that send unauthorized requests.** Cloud Armor evaluates
requests at the edge, before they reach the service, so it cannot count `401`
responses directly. Instead, give it an expression that matches requests that
are bound to fail authentication, and a
[rate-based ban](https://cloud.google.com/armor/docs/rate-limiting-overview):

```bash
# More than 10 requests in a minute without the auth header bans the IP's
# matching requests for that minute plus 30 minutes.
gcloud compute security-policies rules create 1000 \
  --security-policy gcs-webhook-policy \
  --expression "request.path.startsWith('/webhook_acme/') && !has(request.headers['acme-webhook-secret'])" \
  --action rate-based-ban \
  --rate-limit-threshold-count 10 \
  --rate-limit-threshold-interval-sec 60 \
  --ban-duration-sec 1800 \
  --conform-action allow \
  --exceed-action deny-403 \
  --enforce-on-key IP
```

Use the header your `AUTH_MODE` requires: `AUTH_HEADER` for `header` and
`hmac` (e.g. `x-hub-signature-256` for GitHub), `stripe-signature`, or
`webhook-signature` (`svix-signature` for Svix). Header names must be
lowercase. A ban covers only requests that match the rule, so a banned
address's properly authenticated requests still get through.

This catches scanners and requests that don't carry credentials. It can't catch
requests that carry a made-up signature, because only the service can check
that. For `AUTH_MODE=header`, you can make the rule match wrong secrets too, by
adding `|| request.headers['acme-webhook-secret'] != 'THE_SECRET'` inside the
condition. That copies the secret into the security policy, where anyone with
`compute.securityPolicies.get` can read it, and the rule has to be updated
whenever the secret rotates.

**A ceiling for all traffic.** Made-up signatures are what makes large bodies
expensive, so also cap every IP's request rate. Set the threshold well above
your sender's real peak (check the load balancer's request logs):

```bash
gcloud compute security-policies rules create 2000 \
  --security-policy gcs-webhook-policy \
  --expression "request.path.startsWith('/webhook_acme/')" \
  --action rate-based-ban \
  --rate-limit-threshold-count 120 \
  --rate-limit-threshold-interval-sec 60 \
  --ban-duration-sec 600 \
  --conform-action allow \
  --exceed-action deny-429 \
  --enforce-on-key IP
```

Cloud Armor applies the first matching rule in priority order, so requests
without credentials count against rule 1000 and everything else against rule
2000. Rate limits count requests, not bytes. At 120 requests a minute, one IP
can still push `120 × MAX_BODY_BYTES` a minute: 1.2 GiB at 10 MiB, or 12 GiB at
100 MiB. Keep that in mind when raising the limit.

**Allowlist the sender, if you can.** If the sender publishes its source IP
ranges (for example GitHub's `hooks` ranges from `https://api.github.com/meta`,
or Stripe's webhook IPs), the strongest protection is to allow those ranges and
deny everything else on the webhook path:

```bash
gcloud compute security-policies rules create 500 \
  --security-policy gcs-webhook-policy \
  --src-ip-ranges "192.0.2.0/24,198.51.100.0/24" --action allow
gcloud compute security-policies rules create 900 \
  --security-policy gcs-webhook-policy \
  --expression "request.path.startsWith('/webhook_acme/')" --action deny-403
```

Rules with lower numbers win, so with these in place rules 1000 and 2000 never
see traffic on that path. To also cap the allowed sender, give rule 2000 a
priority below 500.

**Banning on actual `401`s.** If you need bans based on the service's real
responses, that requires a feedback loop outside Cloud Armor. The load
balancer's request logs record each request's client IP and status, so you
could route `httpRequest.status=401` entries (through a log sink and Pub/Sub)
to a small function that adds offending IPs to a deny rule and removes them
later. That's more moving parts, but it also catches made-up signatures.

## Development

```bash
# Format
cargo fmt

# Lint
cargo clippy --all-targets -- -D warnings

# Test
cargo test

# End-to-end test of the Docker image against fake-gcs-server (needs docker, curl, jq)
docker build -t gcs-webhook:test . && scripts/integration-test.sh

# Build release
cargo build --release
```

## License

[MIT](LICENSE)
