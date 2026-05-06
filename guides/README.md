# ExDns Guides

Operator-facing guides for installing, deploying, and running ExDns. Read in order if you're new; jump in by topic if you already know what you need.

## Getting started

* [**01 — Installation, configuration & basic operations**](01-installation-and-basic-operations.md)
  Single-node server + Web UI on one host. Install, configure, load a zone, query it, reload, drain.

## Scaling out

* [**02 — Extending to a clustered environment**](02-clustering-with-ekv.md)
  Three-node EKV cluster with replicated state for zones, plugins, TSIG keys, DNSSEC keys, BlackHole.

* [**08 — Secondary zones: AXFR, IXFR, NOTIFY**](08-secondary-zones-axfr-ixfr-notify.md)
  Classic primary/secondary deployment for interop with non-ExDns servers and hidden-primary topologies.

## Choosing how to run

* [**03 — Server modes: authoritative, recursive, stub**](03-server-modes-authoritative-recursive-stub.md)
  When to use each resolver mode and how to compose them with the plugin pipeline.

## Delegating real domains

* [**04 — Delegating your domain (Cloudflare example)**](04-delegating-your-domain.md)
  Complete walk-through: build the zone, expose the server, register glue + change nameservers at the registrar, verify.

## Day-to-day zone management

* [**05 — Zone management via curl**](05-zone-management-via-curl.md)
  Working `curl` cookbook for `/api/v1/*`. Useful for scripts, CI, and chaos test rigs.

* [**06 — Zone management via the Web UI**](06-zone-management-via-the-web-ui.md)
  The UI walkthrough — zones, records, secondaries, DNSSEC keys, plugins.

## DNSSEC

* [**07 — DNSSEC signing & rollover**](07-dnssec-signing-and-rollover.md)
  Sign a zone, register the chain of trust at the registrar, run ZSK and KSK rollovers safely.

## Filtering & plugins

* [**09 — BlackHole filtering (pi-hole-equivalent)**](09-blackhole-filtering.md)
  Set up adlist subscriptions, per-CIDR groups, allow/deny lists, query log inspection.

## Operating it

* [**10 — Monitoring & observability**](10-monitoring-and-observability.md)
  Health probes, Prometheus metrics, structured logs, dnstap, OpenTelemetry tracing, baseline alerts.

## Reference

The authoritative spec for the operator API is the OpenAPI document at [`priv/openapi/v1.yaml`](../priv/openapi/v1.yaml). Every operation in guides 05 and 06 maps to one entry there.

For the deeper "how it actually works" view, the [README](../README.md) sketches the architecture and the [CHANGELOG](../CHANGELOG.md) tracks what shipped when.

## Suggested reading paths

**"I'm evaluating ExDns for my LAN."**
01 → 03 → 09

**"I'm migrating from BIND."**
01 → 03 → 08 (interop) → 07 (DNSSEC) → 10

**"I'm hosting a public domain for the first time."**
01 → 04 → 07 → 08 → 10

**"I want to drive everything from CI/scripts."**
01 → 05 → 02 (if multi-node) → 10

**"I'm operating ExDns in production."**
Skim everything once. Bookmark 02 (cluster), 07 (DNSSEC), 10 (observability).
