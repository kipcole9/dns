# 10 — Monitoring & observability

ExDns ships four overlapping observability surfaces. Pick the ones your environment already speaks; you don't need all four.

| Surface | What it gives you | Cost |
|---|---|---|
| Health probes | Liveness + readiness for systemd / Kubernetes. | Trivial. Always on. |
| Prometheus exporter | Metrics over HTTP — query rates, RRL drops, cache hit ratio, validation outcomes. | Tiny. On by default. |
| Structured logs | Machine-parseable per-query and per-event log. | Modest CPU. Opt-in. |
| dnstap | Binary BIND-compatible firehose of every wire-level event. | Significant disk I/O. Opt-in. |
| OpenTelemetry tracing | Distributed traces of recursive queries. | Modest. Opt-in. |

Every surface emits the same `:telemetry` events under the hood — `[:ex_dns, :query, :stop]`, `[:ex_dns, :recursor, :upstream]`, `[:ex_dns, :dnssec, :validate]`, etc. — so you can also subscribe directly from custom Elixir code.

## Health probes

Bandit on a dedicated port:

```elixir
config :ex_dns, :health,
  enabled: true,
  port: 9572
```

```bash
curl -sS http://127.0.0.1:9572/healthz
# {"status":"ok"}

curl -sS http://127.0.0.1:9572/readyz
# {"status":"ready","checks":{"ekv_quorum":true,"listeners":true,"zones_loaded":true}}
```

Wire into systemd:

```ini
# /etc/systemd/system/exdns.service
[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/local/bin/exdns
WatchdogSec=30s
```

ExDns calls `sd_notify(READY=1)` once `/readyz` would return ready, sends watchdog pings on the configured interval, and emits `STOPPING=1` during graceful drain.

Wire into Kubernetes:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 9572
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /readyz
    port: 9572
  periodSeconds: 5
```

`/readyz` flips to false during drain — load balancers detach the pod before queries start failing.

## Prometheus exporter

```elixir
config :ex_dns, :metrics,
  enabled: true,
  port: 9573
```

Scrape:

```bash
curl -sS http://127.0.0.1:9573/metrics | head
# # HELP ex_dns_queries_total Total queries answered, by transport / qtype / rcode.
# # TYPE ex_dns_queries_total counter
# ex_dns_queries_total{transport="udp",qtype="A",rcode="NOERROR"} 14782
# ex_dns_queries_total{transport="udp",qtype="A",rcode="NXDOMAIN"} 234
# ex_dns_queries_total{transport="tcp",qtype="AXFR",rcode="NOERROR"} 12
# ...
```

Exposed metrics include:

* `ex_dns_queries_total{transport,qtype,rcode}` — counter.
* `ex_dns_query_duration_us_bucket{...}` — histogram per (transport, qtype).
* `ex_dns_recursor_cache_lookups_total{result}` — `hit` / `miss` / `stale`.
* `ex_dns_recursor_upstream_total{server,outcome}` — outcome of every upstream query.
* `ex_dns_dnssec_validate_total{outcome}` — `secure` / `insecure` / `bogus` / `indeterminate`.
* `ex_dns_dnssec_signing_lag_seconds{zone}` — seconds since the latest RRSIG was issued; alert on this.
* `ex_dns_rrl_drops_total{response_kind}` — RRL token-bucket drops.
* `ex_dns_zone_records{apex}` — record count per zone.
* `ex_dns_secondary_state{apex,state}` — gauge with secondary state machine.
* `ex_dns_ekv_quorum{member}` — 1 if member sees quorum, 0 otherwise.

Sample alerts:

```yaml
# DNSSEC signing falling behind.
- alert: ExDnsSigningLag
  expr: max(ex_dns_dnssec_signing_lag_seconds) > 3600
  for: 5m

# Recursor cache hit ratio collapse.
- alert: ExDnsCacheHitRatioLow
  expr: |
    rate(ex_dns_recursor_cache_lookups_total{result="hit"}[5m])
    / rate(ex_dns_recursor_cache_lookups_total[5m])
    < 0.7
  for: 15m

# EKV lost quorum.
- alert: ExDnsEKVNoQuorum
  expr: min(ex_dns_ekv_quorum) == 0
  for: 1m
```

## Structured logs

Compact key=value (logfmt) or JSON, one line per event. Cheaper than dnstap, more queryable than the human log.

```elixir
config :ex_dns, :structured_logs,
  enabled: true,
  format: :logfmt   # or :json
```

```
event=ex_dns.query.start transport=udp qname=www.example.com qtype=a client=10.0.0.5:54201
event=ex_dns.query.stop  transport=udp qname=www.example.com qtype=a rcode=noerror duration_us=820 ans=1
event=ex_dns.recursor.upstream server=192.5.6.30 qname=example.com qtype=ns outcome=ok latency_us=23145
```

Pipe to your log shipper (Vector, Fluentbit, Promtail). Indexes well in Loki / Elasticsearch / OpenSearch.

## dnstap

Binary firehose of every wire-level event in the BIND-compatible dnstap format. Lets you replay traffic into another resolver, feed an offline analysis pipeline, or audit every byte that left the listener.

```elixir
config :ex_dns, :dnstap,
  enabled: true,
  sink: {:file, "/var/log/exdns.dnstap.fstrm"},
  flush_interval_ms: 250
```

`fstrm` is the standard dnstap framing format. Tools that read it: `dnstap-replay`, `dnstap2json`, BIND's `dnstap-read`, GoLang's `dnstap-go`.

This is high-volume. A busy resolver can produce gigabytes per hour. Rotate aggressively, or write to a Unix socket consumed by a sampling collector.

## OpenTelemetry tracing

Distributed tracing of the recursor's iterative walk. Useful when you want to see "this 200ms answer was caused by these four upstream queries to these specific authoritative servers."

```elixir
config :ex_dns, :open_telemetry,
  enabled: true,
  service_name: "exdns",
  service_version: "0.1.0"

# Add the SDK + an exporter (OTLP, Honeycomb, Jaeger, ...).
config :opentelemetry,
  span_processor: :batch,
  traces_exporter: :otlp

config :opentelemetry_exporter,
  otlp_protocol: :grpc,
  otlp_endpoint: "https://otel-collector.observability.svc:4317"
```

Spans emitted: `query`, `resolver.authoritative`, `resolver.recursor`, `recursor.iterate`, `recursor.upstream`, `dnssec.validate`, `plugin.policy_resolve`. Each carries qname / qtype / outcome / size as attributes.

## Live event stream (for dashboards)

The Server-Sent Events feed at `/api/v1/events` is the easiest way to drive an internal dashboard or chat-ops bot:

```bash
TOKEN='<viewer>'
curl -N \
  -H "authorization: Bearer ${TOKEN}" \
  -H "accept: text/event-stream" \
  http://127.0.0.1:9571/api/v1/events
```

Event types: `zone.reloaded`, `zone.record.added`, `zone.record.updated`, `zone.record.deleted`, `secondary.refreshed`, `secondary.state_changed`, `plugin.registered`, `plugin.unregistered`, `dnssec.key.state_changed`, `query.logged` (BlackHole only).

The Web UI uses this stream to live-update without polling.

## CLI inspection

For ad-hoc operator queries:

```bash
bin/exdnsctl status                # server identity, cluster status, listener bindings
bin/exdnsctl zone list             # all loaded zones with serial + record count
bin/exdnsctl zone show example.com # SOA + counts by type
bin/exdnsctl secondary list        # secondary state for every secondary zone
bin/exdnsctl key list              # DNSSEC keys
bin/exdnsctl plugin list           # registered plugins + routes
bin/exdnsctl cluster status        # EKV cluster members + quorum
```

Same data the API would give you, formatted for terminals.

## Suggested baseline

For a single-node deployment that takes itself seriously:

* **Health probes** wired into systemd's `WatchdogSec`.
* **Prometheus** scraped every 15s into a dashboard (Grafana, OSS).
* **Structured logs** to journald → Loki / Elasticsearch.
* **Two alerts**: signing lag > 1h and EKV quorum loss.

For a cluster or any production load:

* All of the above on every member.
* **dnstap** sampled (1%) for periodic deep dives, full firehose only when investigating a specific incident.
* **OpenTelemetry** traces on the recursor path so SLI investigations have request-level detail.

## Related guides

* [01 — Installation, configuration & basic operations](01-installation-and-basic-operations.md)
* [02 — Extending to a clustered environment](02-clustering-with-ekv.md) — for cluster-aware metrics like `ex_dns_ekv_quorum`.
* [07 — DNSSEC signing & rollover](07-dnssec-signing-and-rollover.md) — for the signing-lag alert that you actually want.
