# Changelog

All notable changes to ExDns. Newest first.

## Unreleased

### Added — clustering substrate

* `ExDns.EKV` — single shared instance of the [EKV](https://hex.pm/packages/ekv) embedded KV store. Identical API single-node and clustered, namespaced by key prefix (`plugin/...`, `tsig/...`, `dnssec/...`, `blackhole/...`, `zone/...`).
* `ExDns.Plugin.Registry.Backend.EKV` — default cluster-replicated plugin registry. Override with `config :ex_dns, :plugin_registry, backend: ExDns.Plugin.Registry.Backend.PersistentTerm` for a per-node registry.
* `ExDns.TSIG.Keyring.Backend` behaviour with `Backend.EKV` (default) and `Backend.ETS` adapters. Runtime-installed TSIG keys now propagate cluster-wide.
* `ExDns.DNSSEC.KeyStore.Backend` behaviour with `Backend.EKV` (default) and `Backend.ETS` adapters. DNSSEC signing keys (incoming/active/retired states) replicate across nodes.
* `ExDns.BlackHole.Storage.EKV` — default cluster-replicated BlackHole storage (blocklists / allow / deny / groups / query log). SQLite remains available for high-rate query log workloads.
* `ExDns.Storage.EKV` — default zone storage with an ETS hot-path read cache and EKV write-through for durability and cluster propagation.

### Added — DNS protocol

* `ExDns.NSID` (RFC 5001) — server identification via the OPT NSID option, attached to responses when the client asks. Configured via `:ex_dns, :nsid, [enabled:, identifier:]`.
* `ExDns.Resolver.Default` refuse-ANY mode (RFC 8482) — opt-in HINFO `"RFC8482"` synthetic for QTYPE=ANY.
* `ExDns.Zone.Validate` — SOA monotonicity (RFC 1982 wraparound), in-bailiwick glue, CNAME-coexistence, class match. Wired into `ExDns.Zone.Reload` so bad reloads return `{:error, {:invalid_zone, problems}}`.
* `ExDns.Config` — Elixir-data config-file loader. Triggered at boot via `EXDNS_CONFIG` env var or `:config_file` Application env.
* `ExDns.RPZ.{Match, Store, Resolver, Loader}` — RPZ runtime application with action materialisation (`:nxdomain`, `:nodata`, `:passthru`, `:drop`, `:tcp_only`, `{:redirect, target}`, `{:synthesise, records}`).
* `ExDns.Recursor.Prefetch` + extended `Recursor.Cache` — async re-resolution of popular records before TTL expiry.
* RFC 8767 serve-stale via `Recursor.Cache.lookup_stale/2` and `Iterator.maybe_serve_stale/3`.
* `ExDns.Resolver.{PerZone, PerZoneRouter}` — per-zone forwarding with longest-suffix match.
* `ExDns.Update.TSIG` (RFC 3007) — TSIG verification + response signing for inbound RFC 2136 UPDATE. Operator-tunable `:require_tsig` policy.
* `ExDns.Zone.Snapshot` + `ExDns.Zone.Snapshot.Writer` — runtime mutations (UPDATE, AXFR, catalog applies) survive restart via a debounced binary snapshot.
* `ExDns.Zone.Additionals` — auto-derive A / AAAA glue records for any NS / MX / SRV target present in answer or authority sections.
* `ExDns.DNSSEC.NSEC3.Proof` + `DNSSEC.DenialOfExistence` — per-zone NSEC vs NSEC3 selection. Operators opt-in NSEC3 via `:dnssec_zones`.
* `ExDns.Zone.Catalog.Subscription` — polling state machine for catalog zones (RFC 9432).
* Per-resource `ExDns.Resource.JSON` behaviour with `encode_rdata/1` + optional `decode_rdata/1` on every record type.

### Added — operator surface

* Formal HTTP API at `/api/v1/*` documented in `priv/openapi/v1.yaml` (OpenAPI 3.1). `mix exdns.openapi.check` enforces drift in CI.
* `ExDns.API.Router` with read + mutating routes (zones / records / secondaries / keys / plugins / metrics / events / health / ready), plus rollover phase advancement and per-plugin actions.
* `ExDns.API.Auth` — bearer-token authentication with role hierarchy (`viewer < zone_admin < cluster_admin`) and per-zone-glob scoping. Tokens issued via `mix exdns.token.issue`.
* `ExDns.API.TokenStore` — file-backed token registry with constant-time secret comparison.
* `ExDns.API.Events` + `ExDns.API.SSE` — Server-Sent Events stream for live updates.
* `ExDns.API.MetricsCounters` — telemetry-attached counter aggregator backing `/api/v1/metrics/summary`.

### Added — plugin framework

* `ExDns.Plugin` behaviour (metadata + UI declaration + resource fetcher).
* `ExDns.Plugin.Policy` behaviour — CIDR-routed `routes/0` + `policy_resolve/2`. Dispatch is longest-prefix → priority → registration order.
* `ExDns.Plugin.Action` behaviour — mutating `handle_action/2`, exposed at `POST /api/v1/plugins/:slug/actions/:name` with scope `"plugin:<slug>"`.
* `ExDns.Plugin.Registry` with backend abstraction (`Registry.Backend` + `Backend.PersistentTerm` default), `match/1`, `update_routes/2`, `dispatch_action/3`.
* `ExDns.Resolver.Plugins` — wrapper that consults the registry's route table before deferring to the underlying resolver. Pass-through is the floor.

### Added — plugins shipped in-tree

* `ExDns.BlackHole.Plugin` — pi-hole-equivalent: subscriber-managed adlists (hosts / dnsmasq / AdGuard / plain-domain), allow / deny / groups, query log, dashboard. SQLite-backed via the `ExDns.BlackHole.Storage` behaviour. Includes `BlackHole.QueryLog` (buffered batch writer) and `BlackHole.QueryLog.Sweeper` (age + count retention).
* `ExDns.Anycast.Plugin` — per-region answer synthesis from CIDR + `qname_suffix` to A / AAAA targets.
* `ExDns.MDNS.Plugin` — exposes the local mDNS visualizer as a plugin tab.

### Added — `dns_ui` sibling app

* Separate Mix project at `~/Development/dns_ui/`, zero compile-time coupling to `:ex_dns`.
* Phoenix LiveView with every-layout.dev primitives (Box / Stack / Cluster / Sidebar / Switcher / Center / Cover) and CSS-token light / dark mode.
* `DnsUi.ApiClient` — typed Req-based client mirroring the OpenAPI v1 contract.
* `DnsUi.Accounts` — file-backed user store with PBKDF2-HMAC-SHA256 hashed passwords. Mix tasks `dns_ui.user.create`, `dns_ui.user.list`, `dns_ui.user.delete`.
* `DnsUiWeb.Auth` — session-based auth plug + LiveView `on_mount` hook; per-LV-process bearer token wired through to `ApiClient`.
* `LoginLive` + `SessionController` — sign in / sign out flow.
* `ZonesLive` / `ZoneLive` (with inline edit / add / delete / reload), `SecondariesLive` (status + force-refresh), `KeysLive` (rollover wizard), `PluginsLive` + `PluginTabLive` (generic table / kv / log views), `BlackHoleLive` (custom dashboard with polling live query feed).

### Fixed

* `ExDns.Resource.{decode_class, decode_type}` — catch-all clauses for unhandled integer values (incl. 0 and 65535). Fixed an intermittent fuzz crash.
* `ExDns.Storage.ETS` — `zones/0` and `dump_zone/1` now detect + clean up stale per-zone ETS table refs whose owner exited. Fixed an intermittent test-ordering flake.
* `Resources.keys/0` — was referencing the non-existent `KeyStore.all_signing_keys/0`; now iterates `Storage.zones()` + `KeyStore.signing_keys/1` per zone.
* `Resources.metrics_summary/1` — was returning hardcoded zeros; now wired to `ExDns.API.MetricsCounters`.

### Plans

* `plans/2026-05-06-blackhole-plugin.md` — design + sequencing for the BlackHole plugin.
* `plans/2026-05-06-server-clustering-via-ekv.md` — proposed adoption of EKV (Chris McCord's embedded KV) as the cluster store across zone storage, DNSSEC keys, TSIG keyring, BlackHole config, and the plugin registry. Single library covers single-node + clustered deployments without a schema migration.

### Notes for operators

* All new subsystems are off by default. Operators opt in via `:enabled` flags in `:ex_dns, :api`, `:zone_snapshot`, `:black_hole`, `:anycast`. The DNS protocol surface is fully active without any of them.
* Tests: ~1200 server-side, 21 UI-side. Stable across seeded runs.
