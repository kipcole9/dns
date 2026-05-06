# 03 — Server modes: authoritative, recursive, stub

ExDns ships several resolver modes in one binary. The mode is a configuration choice (`:resolver_module`), not a separate build. This guide explains each mode, when to use it, and shows the configuration.

## TL;DR

| Mode | Module | Use when |
|---|---|---|
| **Authoritative** | `ExDns.Resolver.Default` | You own the zones; you publish answers to the world. |
| **Hybrid** | `ExDns.Resolver.Hybrid` | You're authoritative for some zones AND want to recurse for everything else (typical home / SOHO). |
| **Recursive** | `ExDns.Resolver.Default` + `recursion: true` | You serve recursion to clients but host no zones. |
| **Forwarder / stub** | `ExDns.Resolver.Forwarder` | Don't recurse yourself — hand queries to `1.1.1.1` / `8.8.8.8` / a corporate resolver. |
| **Per-zone forwarder** | `ExDns.Resolver.PerZoneRouter` | Split horizon — forward `*.internal` to one upstream, everything else to another. |
| **Plugin pipeline** | `ExDns.Resolver.Plugins` (wraps any of the above) | You want CIDR-routed plugins (BlackHole, Anycast, mDNS) to consult queries first. |

These compose. A typical operator deployment is: authoritative for owned zones, hybrid recursion for everything else, plugin pipeline on top.

## Authoritative — "I own these zones"

You hold the master copy of one or more zones, queries arrive from the world, you serve the answers. Anything you don't own returns `REFUSED` (recursion disabled) or recurses (hybrid).

```elixir
config :ex_dns,
  resolver_module: ExDns.Resolver.Default,
  zones: ["/etc/exdns/zones.d/*.zone"]

# Optional: turn off recursion entirely so we never look outside our zones.
config :ex_dns, recursion: false
```

This is the right mode for:

* **Public-facing nameservers** for a domain you registered ([04 — Delegating your domain](04-delegating-your-domain.md)).
* **Hidden masters** that feed secondaries via AXFR / IXFR / NOTIFY ([08 — Secondary zones](08-secondary-zones-axfr-ixfr-notify.md)).
* **Internal zone serving** behind a corporate firewall.

What you get: NXDOMAIN with AA=1 for missing names, NODATA with AA=1 for missing types, NS delegation responses with glue, CNAME chasing within the zone, wildcard expansion per RFC 4592, SOA-in-authority for negative caching, RRSIG when DNSSEC is configured.

What you don't get: any answer for names outside your zones. Use **hybrid** if you want both.

## Hybrid — authoritative + recursive

The default deployment for someone running their own DNS at home or in a small office: serve your own `home.lan` authoritatively, recurse to the public DNS for everything else.

```elixir
config :ex_dns,
  resolver_module: ExDns.Resolver.Hybrid,
  zones: ["/etc/exdns/zones.d/*.zone"]

config :ex_dns, recursion: true

# Tune the recursor's cache and prefetch.
config :ex_dns,
  recursor_prefetch_enabled: true,
  recursor_prefetch_fraction: 0.1,
  recursor_serve_stale_ttl: 86_400   # RFC 8767
```

Behaviour:

1. Query arrives, RD=1, qname falls under a zone we host → answer authoritatively (RA=1, AA=1).
2. RD=1, qname is outside our zones → iterative recursion from the root hints, validate DNSSEC, cache, return.
3. RD=0 → answer authoritatively if we have it, otherwise REFUSED. (No client should send RD=0 to a recursor; this is the conservative behaviour.)

The recursor implements RFC 9156 QNAME minimisation (every upstream sees only as much of the qname as it needs), RFC 8198 aggressive NSEC, RFC 8767 serve-stale, and prefetch-on-near-expiry.

## Pure recursive — "I serve the LAN, I host nothing"

```elixir
config :ex_dns,
  resolver_module: ExDns.Resolver.Default,
  zones: []

config :ex_dns, recursion: true
```

Same as hybrid, but with no authoritative zones. Useful as the LAN's recursive resolver, the cache layer in front of `1.1.1.1`, or the inner half of a corporate split-horizon setup.

## Forwarder / stub — "Hand my queries to someone else"

The opposite of recursive: don't walk the hierarchy yourself, send each query to a configured upstream and relay the response. This is what most home routers do.

```elixir
config :ex_dns,
  resolver_module: ExDns.Resolver.Forwarder

config :ex_dns, :forwarder,
  upstreams: [
    {{1, 1, 1, 1}, 53},
    {{1, 0, 0, 1}, 53},
    {{8, 8, 8, 8}, 53}
  ],
  timeout: 5_000
```

Pick this when:

* You don't want the BEAM doing iterative recursion under load — let a hyperscaler do the lookups.
* You're deploying a thin cache-in-front-of-a-cache. The recursor cache still works; you skip the iterative walk.
* You're behind a corporate firewall that only allows DNS to a specific resolver.

`upstreams` is tried in order. Failover happens on timeout or SERVFAIL.

## Per-zone forwarder — split horizon

Different upstreams for different name suffixes. The classic case: corporate `*.internal` zones live on the corporate resolver; everything else goes to a public one.

```elixir
config :ex_dns,
  resolver_module: ExDns.Resolver.PerZoneRouter

config :ex_dns, :per_zone_forwarders, %{
  "internal.example" => [{{10, 0, 0, 5}, 53}, {{10, 0, 0, 6}, 53}],
  "ad.example"       => [{{10, 0, 0, 5}, 53}],
  # No fallthrough entry → unmatched suffixes go to the default forwarder.
}

config :ex_dns, :forwarder,
  upstreams: [{{1, 1, 1, 1}, 53}]
```

The router does longest-suffix match against the qname. `*.internal.example` and `internal.example` both match the first entry; `www.example.com` falls through to the default upstream.

## Plugin pipeline — wrap any mode

The plugin pipeline (`ExDns.Resolver.Plugins`) wraps an underlying resolver and lets registered plugins intercept queries based on CIDR + qname-suffix routes. Pass-through is the floor: queries that don't match any plugin route flow straight to the underlying resolver as if no plugins existed.

```elixir
config :ex_dns,
  resolver_module: ExDns.Resolver.Plugins

config :ex_dns, :plugin_pipeline,
  underlying: ExDns.Resolver.Hybrid    # or Default / Forwarder / PerZoneRouter
```

This is what enables BlackHole filtering, Anycast per-region answers, and any plugin you write yourself. Three plugins ship in-tree:

* **BlackHole** — pi-hole-equivalent. CIDRs of clients to filter, blocklist subscriptions, allow / deny lists. See [09 — BlackHole filtering](09-blackhole-filtering.md).
* **Anycast** — per-region answer synthesis. CIDRs scoped by `qname_suffix`. The CDN-edge primitive.
* **mDNS visualizer** — the local mDNS network's discovered services as a UI tab.

You can run the plugin pipeline on top of any of the modes above. The most common production wiring is:

```elixir
config :ex_dns,
  resolver_module: ExDns.Resolver.Plugins

config :ex_dns, :plugin_pipeline,
  underlying: ExDns.Resolver.Hybrid

config :ex_dns, recursion: true
config :ex_dns, zones: ["/etc/exdns/zones.d/*.zone"]
```

## Choosing the right mode — decision tree

```
Do you OWN domains and need to publish them to the world?
├── Yes → Authoritative (+ Hybrid if you also want recursion for clients)
└── No
    Do you serve recursion to your LAN / clients?
    ├── Yes
    │   Do you want to recurse yourself or hand it to an upstream?
    │   ├── Recurse yourself → Recursive (Default + recursion: true)
    │   └── Hand off          → Forwarder (or PerZoneRouter for split horizon)
    └── No → You don't need ExDns; you need a stub library.
```

## Switching modes is a config change, not a redeploy

Every mode lives in the same binary. Edit `config/runtime.exs`, restart the node — that's it. Zone files, EKV state, TSIG keys, DNSSEC keys, plugin registrations all carry over.

## Related guides

* [01 — Installation, configuration & basic operations](01-installation-and-basic-operations.md)
* [02 — Extending to a clustered environment](02-clustering-with-ekv.md)
* [04 — Delegating your domain](04-delegating-your-domain.md) — for the authoritative path.
