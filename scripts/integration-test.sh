#!/usr/bin/env bash
# End-to-end test: runs the image against fake-gcs-server and checks that a
# webhook is written to the bucket with its metadata.
#
# Usage: scripts/integration-test.sh [image]   (default: gcs-webhook:test)
# Requires: docker, curl, jq
set -euo pipefail

IMAGE="${1:-gcs-webhook:test}"
FAKE_GCS_IMAGE="${FAKE_GCS_IMAGE:-fsouza/fake-gcs-server:1}"
NET="gcs-webhook-it-$$"
BUCKET="webhooks"
SECRET="integration-secret"
GCS="http://localhost:4443"
APP="http://localhost:8080"

fail() {
  echo "FAIL: $*" >&2
  echo "--- gcs-webhook logs ---" >&2
  docker logs "$NET-app" >&2 || true
  exit 1
}

cleanup() {
  docker rm -f "$NET-app" "$NET-gcs" > /dev/null 2>&1 || true
  docker network rm "$NET" > /dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() {
  local url="$1"
  for i in $(seq 1 20); do
    if curl -sf "$url" > /dev/null; then
      echo "$url is up after ${i}s"
      return 0
    fi
    sleep 1
  done
  fail "$url did not come up"
}

docker network create "$NET" > /dev/null

docker run -d --name "$NET-gcs" --network "$NET" --network-alias gcs -p 4443:4443 \
  "$FAKE_GCS_IMAGE" -scheme http -port 4443 -backend memory -external-url http://gcs:4443 > /dev/null
wait_for "$GCS/storage/v1/b"
curl -sf -X POST "$GCS/storage/v1/b?project=test" \
  -H "Content-Type: application/json" -d "{\"name\":\"$BUCKET\"}" > /dev/null

docker run -d --name "$NET-app" --network "$NET" -p 8080:8080 \
  -e GCS_BUCKET="$BUCKET" \
  -e STORAGE_EMULATOR_HOST=http://gcs:4443 \
  -e WEBHOOK_PATH_PREFIX=/webhook_acme/ \
  -e AUTH_MODE=header \
  -e AUTH_HEADER=Acme-Webhook-Secret \
  -e AUTH_SECRET="$SECRET" \
  -e UPLOAD_CHUNK_BYTES=262144 \
  "$IMAGE" > /dev/null
wait_for "$APP/health"

status() { curl -s -o /dev/null -w "%{http_code}" "$@"; }

# Unauthenticated and wrong-secret requests are rejected.
[ "$(status -X POST "$APP/webhook_acme/orders" -d '{}')" = "401" ] || fail "missing secret not rejected"
[ "$(status -X POST "$APP/webhook_acme/orders" -H "Acme-Webhook-Secret: nope" -d '{}')" = "401" ] \
  || fail "wrong secret not rejected"
# Paths outside the prefix and other methods are rejected.
[ "$(status -X POST "$APP/elsewhere" -H "Acme-Webhook-Secret: $SECRET" -d '{}')" = "404" ] \
  || fail "path outside prefix not rejected"
[ "$(status "$APP/webhook_acme/orders")" = "405" ] || fail "GET not rejected"

objects() { curl -sf "$GCS/storage/v1/b/$BUCKET/o" | jq -r '[.items // [] | .[].name] | sort | .[]'; }
[ -z "$(objects)" ] || fail "rejected requests wrote objects: $(objects)"

# A valid webhook is stored; the response arrives only after both writes.
PAYLOAD='{"event":"order.created","order":{"id":42}}'
RESPONSE=$(curl -sf -X POST "$APP/webhook_acme/orders?source=it" \
  -H "Acme-Webhook-Secret: $SECRET" \
  -H "Content-Type: application/json" \
  -H "X-Delivery-Id: delivery-1" \
  -d "$PAYLOAD") || fail "valid webhook was not accepted"
ID=$(echo "$RESPONSE" | jq -re .id) || fail "response has no id: $RESPONSE"
echo "Stored webhook $ID"

mapfile -t NAMES < <(objects)
[ "${#NAMES[@]}" = "2" ] || fail "expected 2 objects, got: ${NAMES[*]}"
BODY_OBJ=$(printf '%s\n' "${NAMES[@]}" | grep -v '\.meta\.json$')
META_OBJ=$(printf '%s\n' "${NAMES[@]}" | grep '\.meta\.json$')
[[ "$BODY_OBJ" == webhook_acme/orders/dt=*/*_"$ID".json ]] || fail "unexpected body object name: $BODY_OBJ"
[ "$META_OBJ" = "${BODY_OBJ%.json}.meta.json" ] || fail "metadata not next to body: $META_OBJ"

download() { curl -sf "$GCS/storage/v1/b/$BUCKET/o/$(jq -rn --arg n "$1" '$n|@uri')?alt=media"; }
[ "$(download "$BODY_OBJ")" = "$PAYLOAD" ] || fail "stored body differs from payload"

META=$(download "$META_OBJ")
check() { echo "$META" | jq -e "$1" > /dev/null || fail "metadata check failed: $1"$'\n'"$META"; }
check ".id == \"$ID\""
check '.method == "POST"'
check '.path == "/webhook_acme/orders"'
check '.query == "source=it"'
check '.auth_mode == "header"'
check '.headers["x-delivery-id"] == ["delivery-1"]'
check '.headers["acme-webhook-secret"] == ["[REDACTED]"]'
check ".body.uri == \"gs://$BUCKET/$BODY_OBJ\""
check ".body.size == ${#PAYLOAD}"
check ".body.sha256 == \"$(printf '%s' "$PAYLOAD" | sha256sum | cut -d' ' -f1)\""

# The secret never reaches the bucket.
if download "$META_OBJ" | grep -q "$SECRET"; then fail "secret leaked into metadata"; fi

docker logs "$NET-app" 2>&1 | grep -q '"message":"Webhook stored"' || fail "no 'Webhook stored' log entry"

# --- Large bodies are streamed to GCS in chunks (resumable upload) ---
TMP=$(mktemp -d)
trap 'cleanup; rm -rf "$TMP"' EXIT
head -c 1200000 /dev/urandom > "$TMP/big.bin"   # ~4.6 chunks of 256 KiB
gzip -c "$TMP/big.bin" > "$TMP/big.bin.gz"
RESPONSE=$(curl -sf -X POST "$APP/webhook_acme/big" \
  -H "Acme-Webhook-Secret: $SECRET" \
  -H "Content-Type: application/octet-stream" \
  -H "Content-Encoding: gzip" \
  --data-binary @"$TMP/big.bin.gz") || fail "large webhook was not accepted"
BIG_ID=$(echo "$RESPONSE" | jq -re .id)
BIG_OBJ=$(objects | grep "_$BIG_ID.bin$") || fail "large body object not found"
docker logs "$NET-app" 2>&1 | grep "\"id\":\"$BIG_ID\"" | grep -q '"streamed":true' \
  || fail "large body was not streamed"
curl -sf "$GCS/storage/v1/b/$BUCKET/o/$(jq -rn --arg n "$BIG_OBJ" '$n|@uri')" \
  | jq -e '.contentEncoding == "gzip"' > /dev/null || fail "contentEncoding not set on object"
# Stored byte-for-byte as sent (still gzipped)...
curl -sf -H "Accept-Encoding: gzip" \
  "$GCS/storage/v1/b/$BUCKET/o/$(jq -rn --arg n "$BIG_OBJ" '$n|@uri')?alt=media" > "$TMP/stored.gz"
cmp -s "$TMP/stored.gz" "$TMP/big.bin.gz" || fail "streamed body differs from what was sent"
# ...and GCS transparently decompresses it for clients that don't accept gzip.
download "$BIG_OBJ" | cmp -s - "$TMP/big.bin" || fail "transcoded download differs from original"
META=$(download "${BIG_OBJ%.bin}.meta.json")
check ".body.size == $(stat -c %s "$TMP/big.bin.gz")"
check ".body.sha256 == \"$(sha256sum "$TMP/big.bin.gz" | cut -d' ' -f1)\""
check '.body.content_encoding == "gzip"'
echo "Streamed webhook $BIG_ID"

# A streamed body that fails authentication leaves nothing behind.
BEFORE=$(objects | wc -l)
[ "$(status -X POST "$APP/webhook_acme/big" -H "Acme-Webhook-Secret: nope" --data-binary @"$TMP/big.bin")" = "401" ] \
  || fail "unauthenticated large body not rejected"
[ "$(objects | wc -l)" = "$BEFORE" ] || fail "rejected large body created objects"

# Bodies over the limit are rejected (default MAX_BODY_BYTES is 10 MiB).
head -c $((10 * 1024 * 1024 + 1)) /dev/zero > "$TMP/huge.bin"
[ "$(status -X POST "$APP/webhook_acme/huge" -H "Acme-Webhook-Secret: $SECRET" --data-binary @"$TMP/huge.bin")" = "413" ] \
  || fail "oversized body not rejected"

# HTTP/2 cleartext (Cloud Run --use-http2) works too.
[ "$(status --http2-prior-knowledge -X POST "$APP/webhook_acme/h2" -H "Acme-Webhook-Secret: $SECRET" -d '{}')" = "200" ] \
  || fail "h2c request failed"

echo "All integration tests passed"
