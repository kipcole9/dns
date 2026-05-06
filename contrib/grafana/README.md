# Grafana dashboard for ExDns

`exdns.json` is a ready-to-import Grafana dashboard that
talks to the Prometheus exporter shipped with ExDns at
`:9573/metrics`.

## Importing

1. Grafana → **Dashboards** → **New** → **Import**.
2. Upload `exdns.json` (or paste its contents).
3. Pick your Prometheus datasource when prompted.
4. Save.

The dashboard sets up an `instance` template variable so
you can filter by host once you scale past one server.

## Panels

| Row | Panel | What it shows |
|---|---|---|
| 1 | QPS | Total queries / second (last 5 min). |
| 1 | Cache hit % | Recursor cache hit ratio. |
| 1 | RRL drops | Token-bucket drops (last 5 min). |
| 1 | EKV quorum | Boolean — green when quorum is healthy. |
| 2 | Queries by rcode | NOERROR / NXDOMAIN / SERVFAIL / REFUSED rates. |
| 2 | Query latency | p95 / p99 of `ex_dns_query_duration_us`. |
| 3 | DNSSEC outcomes | secure / insecure / bogus / indeterminate rates. |
| 3 | Signing lag | Worst per-zone gap since last RRSIG; alert at >1 h. |
| 3 | Loaded zones | Zone count gauge. |

## Required scrape config

Minimum Prometheus config:

```yaml
scrape_configs:
  - job_name: exdns
    static_configs:
      - targets: ["10.0.0.1:9573", "10.0.0.2:9573"]
```

## Suggested alerts (not in the JSON yet)

```yaml
- alert: ExDnsSigningLag
  expr: max(ex_dns_dnssec_signing_lag_seconds) > 3600
  for: 5m

- alert: ExDnsEKVNoQuorum
  expr: min(ex_dns_ekv_quorum) == 0
  for: 1m

- alert: ExDnsServfailRate
  expr: |
    sum(rate(ex_dns_queries_total{rcode="SERVFAIL"}[5m]))
    / sum(rate(ex_dns_queries_total[5m])) > 0.05
  for: 10m
```

Drop these in your Alertmanager rules file.
