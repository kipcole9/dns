# ExDns

Elixir-native DNS server. Authoritative + recursive in one binary, with a formal HTTP API for operators, a separate web UI sibling app (`dns_ui`), and a plugin framework that ships pi-hole-equivalent filtering (BlackHole), per-region answer synthesis (Anycast), and a live mDNS browser out of the box.

> **Status:** ~1200 tests passing. Suitable for evaluation + small / single-node production. Multi-node clustering is designed-for but unshipped — see `plans/2026-05-06-server-clustering-via-ekv.md`.

## What it does

### DNS protocol

Every modern DNS RFC the average operator cares about, plus the bitstring-based wire codec that backs them.

* **Authoritative** serving with NXDOMAIN / NODATA / NS delegation / CNAME chasing / wildcards / SOA-in-authority for negative caching.
* **Recursive** resolver with iterative root-hint walk, ETS cache, RFC 2308 negative caching, RFC 9156 QNAME minimisation, RFC 8198 aggressive NSEC, RFC 8767 serve-stale, prefetch-on-near-expiry, per-zone forwarding.
* **Hybrid** mode (authoritative for owned zones, recursive elsewhere) and pure stub-resolver / forwarder mode.
* **DNSSEC** validation (full chain to IANA root anchor) and signing (ZSK + KSK; ECDSA P-256 + Ed25519; NSEC + NSEC3 + opt-out chains; CDS / CDNSKEY auto-publication; per-zone NSEC vs NSEC3 selection; rollover state machine with the prepare → active → retire → purge phases).
* **Transports**: UDP, TCP (ThousandIsland), DoT (RFC 7858), DoH (RFC 8484, both POST + GET), DoQ handler (RFC 9250 — QUIC binding deferred).
* **TSIG** sign + verify both directions, including outbound AXFR and inbound NOTIFY + dynamic UPDATE (RFC 3007).
* **DNS Cookies** (RFC 7873) with optional BADCOOKIE enforcement.
* **EDNS extensions**: ECS (RFC 7871), Padding (RFC 8467), Extended DNS Errors (RFC 8914), Keepalive (RFC 7828), Algorithm Signaling (RFC 6975), NSID (RFC 5001).
* **Refuse-ANY** minimal response per RFC 8482.
* **AXFR** (streaming over multiple TCP messages) and **IXFR** (with persistent journal). NOTIFY in both directions.
* **RFC 2136 Dynamic UPDATE** with per-zone ACLs, prerequisite checking, atomic apply, SOA bump.
* **Catalog zones** (RFC 9432) with the polling subscription state machine.
* **RPZ** parser + runtime application + per-query rule consultation.
* **Zone validation on load** — SOA monotonicity (RFC 1982 wraparound), glue, CNAME-coexistence.
* **Glue auto-derivation** in answers (NS / MX / SRV targets get A / AAAA in additional automatically).
* **Per-zone view ACLs**, transfer ACLs, NOTIFY ACLs, UPDATE ACLs.
* **Response Rate Limiting** (RRL) with token-bucket per `(client_subnet, qname, qtype, response_kind)`, slip mechanism, cookie-validated bypass.

### Operator surface

* **Formal `/api/v1/*` HTTP API** (OpenAPI 3.1 spec at `priv/openapi/v1.yaml`). Bearer-token auth on every endpoint, scoped per zone-glob and per plugin slug. `mix exdns.openapi.check` enforces drift in CI.
* **Bearer tokens** issued via `mix exdns.token.issue --role <viewer|zone_admin|cluster_admin> --scopes "<glob>,…"`.
* **Server-Sent Events** stream at `/api/v1/events` for live updates (zone reloads, secondary state, plugin registry, query log).
* **CLI** — `mix exdns.ctl` (rndc-equivalent) + `bin/exdnsctl` wrapper.
* **Health probes** — `/healthz` + `/readyz` over Bandit on a dedicated port.
* **systemd integration** — sd_notify READY/STOPPING/WATCHDOG.
* **Graceful drain** — readiness flips, listeners close, in-flight workers complete, journal flushes.
* **Persistent zone snapshot** — runtime UPDATE + AXFR + catalog mutations survive restart.
* **Hot reload** — re-read every zone file via the admin API or the CLI.
* **Observability** — Prometheus exporter, dnstap, structured logs (logfmt), OpenTelemetry tracing.

### Plugin framework

CIDR-routed plugin dispatch — every plugin declares the source-IP CIDRs (and optional qtype / qname-suffix filters) it wants to be consulted for. The registry maintains a route table; the resolver does a single longest-prefix lookup per query and dispatches to *at most one* plugin. Queries that don't match any plugin route flow through the underlying resolver as if no plugins existed.

The same primitive serves both kinds of plugin:

* **Filtering plugins** like BlackHole register CIDRs of clients to filter.
* **Synthesis plugins** like Anycast register CIDRs scoped by `qname_suffix` for a specific zone.

Three plugins ship in-tree:

* **BlackHole** (`ExDns.BlackHole.Plugin`) — pi-hole-equivalent. Subscribes to remote adlists (hosts / dnsmasq / AdGuard / plain-domain formats), curates allow / deny lists per group, logs every query with allow/block status, exposes a dashboard. SQLite-backed configuration (pluggable via `ExDns.BlackHole.Storage`); buffered query log with retention sweeper.
* **Anycast** (`ExDns.Anycast.Plugin`) — per-region answer synthesis. Maps source-IP CIDRs to an A / AAAA target. Useful as the building block for a CDN-edge resolver.
* **mDNS visualizer** (`ExDns.MDNS.Plugin`) — exposes the local mDNS network's discovered services as a plugin tab.

Operators bring their own plugins by implementing `ExDns.Plugin` (metadata + UI declaration), optionally `ExDns.Plugin.Policy` (CIDR-routed per-query hook), and optionally `ExDns.Plugin.Action` (mutating UI actions).

### Web UI (`dns_ui`)

A separate Phoenix LiveView Mix project with **zero compile-time coupling** to `:ex_dns`. Lives at `~/Development/dns_ui/`. Talks to the server only via the formal `/api/v1/*` API. Can run on a different host, on a different deploy cadence, against a remote cluster.

Includes:

* Zones list + zone detail (records table with type / name filter, inline edit / add / delete, journal timeline).
* Secondaries status board with per-row force-refresh.
* DNSSEC keys + rollover wizard (prepare / complete / purge).
* Plugins list + per-plugin tabs (generic table / kv views, plus a custom `BlackHoleLive` dashboard with a polling live query feed).
* User accounts + login (PBKDF2-hashed passwords, file-backed user store, `mix dns_ui.user.create`).
* Light / dark / system theme via CSS custom properties + `data-theme` attribute.
* Every-layout.dev primitives (Box / Stack / Cluster / Sidebar / Switcher) — components never set their own external margin.

## Quick start

### Server

```bash
cd ~/Development/dns
mix deps.get
mix test
```

Edit `config/runtime.exs`:

```elixir
import Config

config :ex_dns,
  zones: ["/etc/exdns/zones.d/*.zone"]

config :ex_dns, :nsid, enabled: true, identifier: "ns1.example"

config :ex_dns, :api,
  enabled: true,
  port: 9571,
  bind: {127, 0, 0, 1}

# Snapshot zone state to survive runtime mutations across restart.
config :ex_dns, :zone_snapshot,
  enabled: true,
  path: "/var/lib/exdns/snapshot.bin"

# Pi-hole-equivalent blocklist filtering, opt-in per CIDR.
config :ex_dns, :black_hole,
  enabled: true,
  storage:
    {ExDns.BlackHole.Storage.SQLite,
     [path: "/var/lib/exdns/black_hole.sqlite"]},
  default_block_response: :nxdomain,
  query_log_capacity: 100_000,
  query_log_max_age_seconds: 604_800

# Per-region answer synthesis.
config :ex_dns, :anycast,
  regions: [
    %{
      id: :eu,
      cidrs: [{{198, 51, 100, 0}, 24}],
      qname_suffix: "cdn.example",
      answers: %{a: {192, 0, 2, 1}, aaaa: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}}
    },
    %{
      id: :us,
      cidrs: [{{203, 0, 113, 0}, 24}],
      qname_suffix: "cdn.example",
      answers: %{a: [{192, 0, 2, 2}, {192, 0, 2, 3}]}
    }
  ]

# Wire the plugin pipeline as the resolver entry point.
config :ex_dns,
  resolver_module: ExDns.Resolver.Plugins

config :ex_dns, :plugin_pipeline,
  underlying: ExDns.Resolver.Default
```

Issue an API token:

```bash
mix exdns.token.issue --role zone_admin --scopes "*"
```

Start the server:

```bash
mix run --no-halt
```

### Web UI

```bash
cd ~/Development/dns_ui
mix deps.get

# Create a user mapped to the API token issued above.
mix dns_ui.user.create \
  --email kip@example.com \
  --password 's3cret' \
  --bearer-token '<the token from `mix exdns.token.issue`>'

# Tell the UI where the server's API lives.
EXDNS_API_URL=http://127.0.0.1:9571 mix phx.server
```

Open http://localhost:4000 → sign in → Zones / Secondaries / DNSSEC keys / Plugins.

## Architecture

```
                 ┌─────────────────────────────────────────────────┐
                 │                Wire / Transport                 │
                 │  UDP / TCP / DoT / DoH / DoQ-handler / mDNS     │
                 └────────────────────────┬────────────────────────┘
                                          │
                          ┌───────────────▼───────────────┐
                          │   ExDns.Resolver.Plugins      │
                          │   (CIDR-routed dispatch)      │
                          └─────────┬───────────┬─────────┘
                                    │           │
                  policy match       │           │     no match (passthru)
                                    │           │
                          ┌─────────▼───┐   ┌───▼─────────────────────────┐
                          │   Plugin    │   │   ExDns.Resolver.Default    │
                          │   Registry  │   │   (or Hybrid / Forwarder /  │
                          │             │   │   PerZone / View)            │
                          │  routes/0   │   │                              │
                          │  policy_    │   │   uses:                      │
                          │  resolve/2  │   │   - ExDns.Storage (zones)    │
                          │             │   │   - DNSSEC.Validator         │
                          └─────────────┘   │   - Recursor.{Iterator,Cache}│
                                            └──────────────────────────────┘
                                                          │
                          ┌───────────────────────────────▼───────────────┐
                          │            Operator surface                   │
                          │  ExDns.API.Router  → /api/v1/*                │
                          │  ExDns.Admin       → admin HTTP               │
                          │  ExDns.Health      → /healthz, /readyz        │
                          │  Telemetry → Prometheus / dnstap / OTel       │
                          └───────────────────────────────────────────────┘
                                                          ▲
                                                          │  HTTP + bearer
                                            ┌─────────────┴─────────────┐
                                            │   dns_ui (separate app)   │
                                            │   Phoenix LiveView        │
                                            └───────────────────────────┘
```

Every subsystem named above has a small behaviour-shaped interface so a clustered backend can swap in without changing the resolver, the API, or the plugins. See `plans/2026-05-06-server-clustering-via-ekv.md` for the planned EKV adoption.

## Configuration reference

Documented per subsystem in the moduledoc of each module — start at `ExDns`, `ExDns.Resolver.Default`, `ExDns.API.Router`, and `ExDns.BlackHole.Plugin`.

## Plans

The `plans/` directory holds dated planning documents. Read in order if you're catching up on intent:

* `2026-05-02-revival-plan.md` — what brought ExDns back to life.
* `2026-05-05-competitive-gaps.md` — gap analysis vs BIND / Knot / NSD / PowerDNS / Unbound.
* `2026-05-05-ui-policy-plugins-bind-comparison.md` — UI architecture, plugin framework, BIND parity.
* `2026-05-06-blackhole-plugin.md` — BlackHole plugin (shipped).
* `2026-05-06-server-clustering-via-ekv.md` — proposed EKV adoption for multi-node clustering.

## RFCs implemented



## DNS Testing Sites

* [Pingdom](http://dnscheck.pingdom.com)
* [MX Toolbox DNS check](https://mxtoolbox.com/dnscheck.aspx)
* [Zonemaster](https://github.com/dotse/zonemaster)

## RFCs

### Foundation RFCs

* [DOMAIN NAMES - CONCEPTS AND FACILITIES](https://tools.ietf.org/html/rfc1034)
* [DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://tools.ietf.org/html/rfc1035)
* [Domain Name System (DNS) IANA Considerations](https://tools.ietf.org/html/rfc6895)
* [Clarifications to the DNS Specification](https://tools.ietf.org/html/rfc2181)
* [Binary Labels in the Domain Name System](https://tools.ietf.org/html/rfc2673)
* [Dynamic Updates in the Domain Name System (DNS UPDATE)](https://tools.ietf.org/html/rfc2136)
* [Handling of Unknown DNS Resource Record (RR) Types](https://tools.ietf.org/html/rfc3597)
* [Obsoleting IQUERY](https://tools.ietf.org/html/rfc3425)
* [Requirements for Internet Hosts -- Application and Support](https://tools.ietf.org/html/rfc1123)
* [DNAME Redirection in the DNS](https://tools.ietf.org/html/rfc6672)

### Zone Updates and Replication

* [A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)](https://tools.ietf.org/html/rfc1996)
* [Incremental Zone Transfer in DNS](https://tools.ietf.org/html/rfc1995)

### Resource Records

Many of the RRs are described in [RFC1035](https://tools.ietf.org/html/rfc1035).  Some of the later RRs, or clarifications to them, are listed here:

* [List of DNS record types](https://en.wikipedia.org/wiki/List_of_DNS_record_types)
* [A DNS RR for specifying the location of services (DNS SRV)](https://tools.ietf.org/html/rfc2782)
* [The Role of Wildcards in the Domain Name System](https://tools.ietf.org/html/rfc4592)
* [The Uniform Resource Identifier (URI) DNS Resource Record](https://tools.ietf.org/html/rfc7553)
* [Using the Domain Name System To Store Arbitrary String Attributes](https://tools.ietf.org/html/rfc1464)
* [Extension Mechanisms for DNS (EDNS(0))](https://tools.ietf.org/html/rfc6891)
* [New DNS RR Definitions](https://tools.ietf.org/html/rfc1183)
* [A "Null MX" No Service Resource Record for Domains That Accept No Mail](https://tools.ietf.org/html/rfc7505)
* [DNS Extensions to Support IP Version 6](https://tools.ietf.org/html/rfc3596)
* [A Means for Expressing Location Information in the Domain Name System](https://tools.ietf.org/html/rfc1876)

### Pseudo Resource Records

* `*` and `AXFR` are described in [RFC1035](https://tools.ietf.org/html/rfc1035).
* The `IXFR` record is described in [RFC1996](https://tools.ietf.org/html/rfc1996)
* The `OPT` record is described in [RFC6891](https://tools.ietf.org/html/rfc6891)

### For DNS-SD

* [DNS Long-Lived Queries](http://files.dns-sd.org/draft-dns-llq.txt)
* [Dynamic DNS Update Leases](http://files.dns-sd.org/draft-dns-update-leases.txt)

### IDNA

* [Punycode: A Bootstring encoding of Unicode for Internationalized Domain Names in Applications (IDNA)](https://tools.ietf.org/html/rfc3492)

### Security

* [DNS Security Introduction and Requirements](https://tools.ietf.org/html/rfc4033)
* [Clarifications and Implementation Notes for DNS Security (DNSSEC)](https://tools.ietf.org/html/rfc6840#section-5.7)
* [Domain Name System Security Extensions](https://tools.ietf.org/html/rfc2535)
* [Resource Records for the DNS Security Extensions](https://tools.ietf.org/html/rfc4034)
* [https://tools.ietf.org/html/rfc2065](https://tools.ietf.org/html/rfc2065)
* [Secret Key Transaction Authentication for DNS (TSIG)](https://tools.ietf.org/html/rfc2845)
* [Secret Key Establishment for DNS (TKEY RR)](https://tools.ietf.org/html/rfc2930)
* [Legacy Resolver Compatibility for Delegation Signer (DS)](https://tools.ietf.org/html/rfc3755)
* [A Method for Storing IPsec Keying Material in DNS](https://tools.ietf.org/html/rfc4025)
* [DNS Security (DNSSEC) Hashed Authenticated Denial of Existence](https://tools.ietf.org/html/rfc5155)
* [DNS Security (DNSSEC) Hashed Authenticated Denial of Existence](https://tools.ietf.org/html/rfc5155)



