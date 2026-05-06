# 05 — Zone management via curl

Every operation the Web UI performs is a call against the formal HTTP API at `/api/v1/*`. This guide is a working cookbook for driving that API directly with `curl`. Useful for scripts, ad-hoc edits, CI pipelines, and chaos-engineering test rigs.

The full API contract is the OpenAPI 3.1 document at `priv/openapi/v1.yaml`. `mix exdns.openapi.check` enforces drift in CI.

## Setup

Issue a token once and export it:

```bash
cd ~/Development/dns
mix exdns.token.issue --role zone_admin --scopes "*"
# Copy the secret.

export EXDNS_API="http://127.0.0.1:9571"
export TOKEN='<paste secret here>'

# Helper: every example below uses these.
api() {
  curl -sS \
    -H "authorization: Bearer ${TOKEN}" \
    -H "content-type: application/json" \
    "$@"
}
```

> **Convention.** Every endpoint requires the `Authorization: Bearer …` header. Mutating endpoints additionally require the token's role + scope to cover the target. A `viewer` token can list zones; only `zone_admin` (in scope) or `cluster_admin` can mutate.

## Inspecting the server

```bash
api ${EXDNS_API}/api/v1/server | jq
# {"version": "0.1.0", "nsid": "ns1.example", "listeners": [...], "cluster": {...}}

api ${EXDNS_API}/api/v1/health | jq
# {"status": "ok"}

api ${EXDNS_API}/api/v1/ready | jq
# {"status": "ready", "checks": {...}}
```

`/health` is liveness — is the BEAM up? `/ready` is readiness — is the server able to answer queries (zones loaded, EKV quorum, listeners bound)? Use them as systemd / Kubernetes probes.

## Listing zones

```bash
api ${EXDNS_API}/api/v1/zones | jq
# {"zones": [{"apex": "example.test", "record_count": 12, "soa_serial": 2026010101, ...}, ...]}

api ${EXDNS_API}/api/v1/zones/example.test | jq
# {"apex": "...", "soa": {...}, "counts_by_type": {"A": 7, "NS": 2, ...}}
```

## Listing records — paginated, filtered

```bash
# All records (paginated; default page size 50).
api "${EXDNS_API}/api/v1/zones/example.test/records?limit=50&offset=0" | jq

# Filter by type.
api "${EXDNS_API}/api/v1/zones/example.test/records?type=A" | jq

# Filter by name (exact match against the FQDN).
api "${EXDNS_API}/api/v1/zones/example.test/records?name=www.example.test" | jq

# Combine.
api "${EXDNS_API}/api/v1/zones/example.test/records?type=MX&name=example.test" | jq
```

Response shape:

```json
{
  "records": [
    {
      "id": "01HF7…",
      "name": "www.example.test",
      "type": "A",
      "ttl": 3600,
      "class": "IN",
      "data": "203.0.113.20"
    }
  ],
  "total": 7
}
```

The `id` is opaque, stable for the record's lifetime, and what you use for `update` / `delete`.

## Adding a record

```bash
api -X POST "${EXDNS_API}/api/v1/zones/example.test/records" \
  -d '{
    "name": "api",
    "type": "A",
    "ttl": 300,
    "data": "203.0.113.42"
  }' | jq
```

Returns the created record (with its new `id`). The `name` may be unqualified (`"api"`), in which case the zone apex is appended, or fully qualified (`"api.example.test"`) — both work.

Type-specific `data` shapes:

```bash
# AAAA
'{ "name": "api", "type": "AAAA", "ttl": 300, "data": "2001:db8::42" }'

# CNAME
'{ "name": "blog", "type": "CNAME", "ttl": 300, "data": "ghs.googlehosted.com." }'

# MX (priority + target)
'{ "name": "@", "type": "MX", "ttl": 3600, "data": { "priority": 10, "target": "mail.example.test." } }'

# TXT
'{ "name": "@", "type": "TXT", "ttl": 3600, "data": "v=spf1 mx -all" }'

# SRV
'{ "name": "_xmpp-server._tcp", "type": "SRV", "ttl": 3600,
   "data": { "priority": 10, "weight": 0, "port": 5269, "target": "xmpp.example.test." } }'

# CAA
'{ "name": "@", "type": "CAA", "ttl": 3600,
   "data": { "flags": 0, "tag": "issue", "value": "letsencrypt.org" } }'

# TLSA (DANE)
'{ "name": "_443._tcp.www", "type": "TLSA", "ttl": 3600,
   "data": { "usage": 3, "selector": 1, "matching_type": 1, "data": "<hex>" } }'
```

## Updating a record

You need its `id`. Either remember it from the add response, or look it up:

```bash
ID=$(api "${EXDNS_API}/api/v1/zones/example.test/records?name=api.example.test&type=A" \
     | jq -r '.records[0].id')

api -X PATCH "${EXDNS_API}/api/v1/zones/example.test/records/${ID}" \
  -d '{ "ttl": 60, "data": "203.0.113.99" }'
```

Only the fields you supply are changed. Omitting `ttl` keeps the existing TTL.

## Deleting a record

```bash
api -X DELETE "${EXDNS_API}/api/v1/zones/example.test/records/${ID}"
# 204 No Content
```

## Reloading a zone from disk

If you edited the zone file directly (instead of going through the API), reload it:

```bash
api -X POST "${EXDNS_API}/api/v1/zones/example.test/reload" | jq
# {"reloaded": true, "soa_serial": 2026010102}
```

A failed reload (bad SOA, dangling glue, CNAME conflict) returns the previous SOA serial unchanged and a `problems` array describing what went wrong; the previously-loaded zone keeps serving.

## Bulk update — replace a recordset atomically

The cleanest way to swap several records of one type (say, the apex A records during a server move) is delete-then-add inside a single SOA bump. There's no transactional bulk endpoint today, but the SOA only advances once per write batch when you do the deletes back-to-back:

```bash
# Get all old A records at the apex.
api "${EXDNS_API}/api/v1/zones/example.test/records?name=example.test&type=A" \
  | jq -r '.records[].id' \
  | while read id; do
      api -X DELETE "${EXDNS_API}/api/v1/zones/example.test/records/${id}"
    done

# Insert the new ones.
for ip in 203.0.113.50 203.0.113.51 203.0.113.52; do
  api -X POST "${EXDNS_API}/api/v1/zones/example.test/records" \
    -d "{\"name\":\"@\",\"type\":\"A\",\"ttl\":300,\"data\":\"${ip}\"}"
done
```

For full-RRset replacement with strong consistency, use **RFC 2136 Dynamic UPDATE** with TSIG instead — see [08 — Secondary zones, AXFR / IXFR / NOTIFY](08-secondary-zones-axfr-ixfr-notify.md) for the TSIG setup, then drive the UPDATE with `nsupdate`:

```bash
nsupdate -k /etc/exdns/tsig/ddns.example.key <<EOF
server 127.0.0.1 5353
zone example.test.
update delete example.test. A
update add example.test. 300 A 203.0.113.50
update add example.test. 300 A 203.0.113.51
update add example.test. 300 A 203.0.113.52
send
EOF
```

That is one transaction; the SOA bumps once.

## Watching live changes

The API exposes a Server-Sent Events stream:

```bash
curl -N \
  -H "authorization: Bearer ${TOKEN}" \
  -H "accept: text/event-stream" \
  "${EXDNS_API}/api/v1/events"
```

Events include `zone.reloaded`, `zone.record.added`, `zone.record.updated`, `zone.record.deleted`, `secondary.refreshed`, `plugin.registered`, `plugin.unregistered`, `dnssec.key.state_changed`, `query.logged` (BlackHole). Useful for building dashboards, real-time audit logs, or just watching what the UI is doing.

## Plugin actions and resources

Read-only data from a plugin:

```bash
api "${EXDNS_API}/api/v1/plugins" | jq
api "${EXDNS_API}/api/v1/plugins/black_hole" | jq
api "${EXDNS_API}/api/v1/plugins/black_hole/resources/blocklists" | jq
```

Mutating action against a plugin:

```bash
api -X POST "${EXDNS_API}/api/v1/plugins/black_hole/actions/refresh_blocklist" \
  -d '{ "id": "stevenblack" }'
```

## DNSSEC rollover phase advancement

```bash
# Stage a new ZSK in the published DNSKEY RRset.
api -X POST "${EXDNS_API}/api/v1/keys/example.test/rollover/prepare" \
  -d '{ "role": "zsk" }'

# Activate it (start signing with it).
api -X POST "${EXDNS_API}/api/v1/keys/example.test/rollover/active" \
  -d '{ "role": "zsk", "key_tag": 12345 }'

# Retire the old key (stop signing, keep published).
api -X POST "${EXDNS_API}/api/v1/keys/example.test/rollover/retire" \
  -d '{ "role": "zsk", "key_tag": 67890 }'

# Purge it (remove from the DNSKEY RRset).
api -X POST "${EXDNS_API}/api/v1/keys/example.test/rollover/purge" \
  -d '{ "role": "zsk", "key_tag": 67890 }'
```

See [07 — DNSSEC signing & rollover](07-dnssec-signing-and-rollover.md) for the full lifecycle.

## Error responses

Every error returns JSON with a `code` and a human-readable `message`:

```json
{
  "error": {
    "code": "validation",
    "message": "ttl must be ≥ 0",
    "field": "ttl"
  }
}
```

Common HTTP statuses:

| Status | Meaning |
|---|---|
| `400` | Validation failure (bad JSON, missing field, illegal value). |
| `401` | No token, expired token, or revoked token. |
| `403` | Token is valid but lacks the required role or scope. |
| `404` | Zone / record / plugin / resource not found. |
| `409` | Conflict (e.g. zone reload found a CNAME-coexistence violation). |
| `422` | Semantic error (e.g. SOA serial didn't advance on reload). |
| `429` | Rate-limited (admin API has a soft per-token cap). |
| `5xx` | Server bug — capture the response and the server log. |

## Related guides

* [01 — Installation, configuration & basic operations](01-installation-and-basic-operations.md)
* [06 — Zone management via the Web UI](06-zone-management-via-the-web-ui.md) — the same operations clicked instead of typed.
* [07 — DNSSEC signing & rollover](07-dnssec-signing-and-rollover.md)
* [08 — Secondary zones, AXFR / IXFR / NOTIFY](08-secondary-zones-axfr-ixfr-notify.md)
