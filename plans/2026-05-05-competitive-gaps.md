# Where ExDns is deficient vs. the leading DNS servers

Date: 2026-05-05

## Reference set

* **Authoritative:** BIND 9, Knot DNS, NSD, PowerDNS Authoritative
* **Recursive:** Unbound, BIND 9, PowerDNS Recursor, dnsmasq
* **Hybrid / load-balancer:** dnsdist, CoreDNS

## What we have today (so the gap analysis is honest)

* 24 RR types with bitstring decode/encode (incl. SVCB/HTTPS, DNSSEC RRs, SSHFP, NAPTR, LOC, CAA)
* ETS-backed authoritative resolution: NXDOMAIN/NODATA, AA, CNAME chasing, wildcards, NS delegation + glue, ANY, SOA-in-authority for negative caching
* EDNS0 / OPT — payload-size negotiation, DO-bit echo, AD/CD cleared per RFC 6840
* Name compression on encode, TC fallback for oversized UDP
* Recursive resolution (root hints, ETS cache, iterative resolver, hybrid)
* Cluster: Storage behaviour, `:global` master election, `commit/1` forwarding, optional libcluster
* Policy-based resolution (Request → Policy chain → SourceIp built-in for poor-man's Anycast)
* Transports: UDP, TCP (ThousandIsland), DoH (Bandit + Plug), AXFR, IXFR (→ AXFR fallback), NOTIFY (receive)
* mDNS responder + DNS-SD + probe/announce + cache-flush bit
* mDNS visualizer
* 264 tests, zone-file read+write round-trip

## Gap matrix

Categorised by what each leading server has that we don't.

### Crypto (the biggest gap)

| Capability | Status | Notes |
|---|---|---|
| **DNSSEC signing** (online + offline) | ❌ | We can serve pre-signed zones (DS/DNSKEY/RRSIG/NSEC/NSEC3 decode + serve), but cannot generate signatures. BIND, Knot, PowerDNS all sign online. |
| **DNSSEC validation** (recursive) | ❌ | Recursive resolver returns whatever the upstream sends; no chain-of-trust verification. Unbound's reason for existing. |
| **TSIG** (RFC 8945) | ❌ | Transaction signatures for AXFR/IXFR/NOTIFY/UPDATE auth. Without it, zone-transfer security is "trust the IP". Every real primary/secondary uses TSIG. |
| **SIG(0)** (RFC 2931) | ❌ | TSIG alternative using DNSSEC keys. |
| **DNS Cookies** (RFC 7873) | ❌ | Cheap DDoS mitigation; both client and server cookies. Knot/BIND/PowerDNS all support. |

### Operational maturity

| Capability | Status | Notes |
|---|---|---|
| **Persistent storage** | ❌ | Pure in-memory. Restart drops every zone unless explicitly reloaded from disk via `Zone.load_file/1`. |
| **Configuration files** | ❌ | Only Application env; no `named.conf` / `knot.conf` analogue. |
| **Hot reload** | ❌ | No SIGHUP-style reload of zones / config without restart. |
| **Prometheus / metrics** | ❌ | No counters for query rate, RCODE distribution, cache hit rate, AXFR transfers, etc. |
| **dnstap** (structured logging) | ❌ | Industry-standard structured DNS log format. |
| **Query log** | ❌ | We log nothing per-query; just supervisor-level info logs. |
| **ACLs / allowlists** | ⚠️ | Policy framework could be the foundation but we don't ship an `:allow_query` / `:allow_transfer` style ACL primitive. |
| **AXFR access control** | ❌ | Anyone can `dig AXFR` against us and get the entire zone. Real servers default to deny; allow per-IP via TSIG. |
| **Response Rate Limiting** (RRL) | ❌ | DDoS amplification mitigation. Without it we're a participant in DNS reflection attacks. |
| **Zone validation** | ⚠️ | We accept whatever the parser gives us; no SOA-serial monotonicity check, no glue check, no CNAME-coexistence check. |

### Modern protocol features

| Capability | Status | Notes |
|---|---|---|
| **DNS-over-TLS** (DoT, RFC 7858) | ❌ | We have DoH; DoT is the other half of the privacy-transport pair. |
| **DNS-over-QUIC** (DoQ, RFC 9250) | ❌ | Lower-latency than DoT/DoH; gaining adoption. |
| **EDNS Client Subnet** (ECS, RFC 7871) | ❌ | CDN-grade geo-routing relies on this. Lets the policy resolver know the *client's* subnet, not just the recursor's. |
| **NSID** (RFC 5001) | ❌ | Server identification via EDNS option. We decode the OPT record; we just don't surface NSID. |
| **Padding** (RFC 7830) | ❌ | Privacy padding for DoT/DoH payloads. |
| **Extended DNS Errors** (EDE, RFC 8914) | ❌ | Better than `SERVFAIL` with no detail. |
| **Catalog zones** (RFC 9432) | ❌ | Zone provisioning across the cluster. |
| **DNS UPDATE** (RFC 2136) | ❌ | Dynamic record manipulation via DNS protocol. Used by DHCP integrations and some service discovery. We handle the opcode by returning NOTIMP. |
| **Outbound NOTIFY** | ❌ | We *receive* NOTIFY; we don't *send* them. After a zone change on a primary, secondaries should be poked. |
| **Real IXFR** (with journal) | ⚠️ | We accept IXFR queries but always answer with full AXFR. RFC 1995 allows this fallback; real servers maintain a per-zone journal of changes. |
| **RPZ** (Response Policy Zones) | ❌ | DNS firewall — block/redirect responses by policy zone. BIND-originated; widely deployed. |
| **Views / split-horizon** | ⚠️ | Our policy chain could be the foundation; we don't ship a "view" abstraction with per-view zone sets. |

### Recursive-specific (vs. Unbound)

| Capability | Status | Notes |
|---|---|---|
| **DNSSEC validation** | ❌ | (Listed above; biggest item.) |
| **QNAME minimisation** (RFC 9156) | ❌ | Privacy improvement — send minimum necessary qname to upstream. |
| **Aggressive NSEC use** (RFC 8198) | ❌ | Use cached NSEC ranges to synthesise negative answers. |
| **Prefetching** | ❌ | Refresh popular records ~10% before TTL expiry. |
| **Serve stale** (RFC 8767) | ❌ | Continue serving expired records during upstream outages. |
| **Forwarding configuration** | ❌ | "For zone X, forward to upstream Y" rules. |
| **Negative caching** | ⚠️ | We honor SOA TTL on the inbound recursion path implicitly; not as a first-class concept. |

### High-performance / hardening

| Capability | Status | Notes |
|---|---|---|
| `SO_REUSEPORT` multi-socket scaling | ❌ | Modern UDP servers open one socket per CPU and let the kernel hash to spread load. |
| `recvmmsg` / `sendmmsg` | ❌ | Batched syscalls cut UDP overhead substantially. |
| Source-port randomisation | ⚠️ | We use `0` (kernel pick) for outbound recursive queries; that gives entropy but no explicit reseeding. |
| Refuse `ANY` (RFC 8482) | ❌ | We answer ANY fully — useful for our own admins, dangerous on the public internet (amplification). Should at minimum offer a "minimal ANY" mode. |

## Recommended top three to address

The single most impactful tranches of work, ordered:

### 1. Cryptographic security: DNSSEC + TSIG

The single biggest competitive gap. Modern DNS expects cryptographic
authenticity end to end, and zone transfers between organisations
expect TSIG.

* **DNSSEC signing** — generate RRSIG/NSEC/NSEC3 records for served
  zones. Use Erlang's `:public_key` for ECDSA P-256 / Ed25519. Auto-roll
  ZSK; KSK rollover documented. Online signing ("on-the-fly" per
  query) and offline signing (presign + cache) variants.
* **DNSSEC validation** — recursive resolver verifies the chain of
  trust from the IANA root KSK down. Cache validated DS/DNSKEY records.
  Surface bogus/insecure/secure status.
* **TSIG** (RFC 8945) — HMAC-SHA-256 by default. Verify signatures on
  inbound AXFR/IXFR/NOTIFY/UPDATE; sign outbound. Per-zone keyrings.
* **DNS Cookies** (RFC 7873) — cheap DoS-amplification mitigation;
  comes naturally as part of the EDNS-options work this unlocks.

Why this is #1: without it we're a "fun" DNS server, not a production
one. Every other category below depends on the cluster being
trustable.

### 2. Operational maturity: persistence, metrics, ACLs, RRL, hot reload

A server that ops teams can deploy with confidence.

* **On-disk zone storage** — periodic snapshot + journal so a restart
  doesn't lose pushed zones. Independent of the in-memory ETS/Khepri
  story; both backends should be able to cold-start from disk.
* **Configuration files** — TOML or HCL or Elixir-data; zones list,
  ACLs, listener config, key material references. Currently you set
  things via Application.put_env, which is fine for tests but not for
  ops.
* **Hot reload** — re-read config on signal/HTTP; swap zones atomically.
* **Prometheus exporter** — query counters by RCODE / type / zone,
  latency histograms, cache hit ratios, AXFR transfer counts, election
  state.
* **Structured query log** + **dnstap** for tracing.
* **ACLs** — first-class `:allow_query`, `:allow_transfer`,
  `:allow_notify`, `:allow_update` keyed by IP / TSIG key. The policy
  framework is the right substrate; we just need the named primitive.
* **Response Rate Limiting** — Knot's algorithm is the reference
  (responses-per-second per source-prefix, with SLIP). Without this we
  *are* a DDoS amplifier.
* **`refuse-any` mode** for public deployments (RFC 8482).

Why this is #2: the protocol features can be world-class but if
operators can't reload a zone or see what's happening, the server
won't get deployed.

### 3. Modern privacy & extension surface: DoT, DoQ, ECS, EDE, padding

The current EDNS0 work covered baseline negotiation. The next layer
is the privacy / observability transports and EDNS options that the
modern internet expects.

* **DoT** (RFC 7858) — TLS over TCP/853. Bandit (already a dep) does
  TLS; reuse the TCP listener with a TLS upgrade.
* **DoQ** (RFC 9250) — DNS over QUIC. There's a budding Erlang QUIC
  ecosystem (Mint+kQUIC, Quicer). Lower-latency than DoT.
* **EDNS Client Subnet** (RFC 7871) — pass the client's actual subnet
  through to the policy chain, so source-IP routing works through
  recursors (today our SourceIp policy only sees the recursor's IP).
* **Extended DNS Errors** (RFC 8914) — replace `SERVFAIL` with
  detailed error codes (signature expired, no reachable authority,
  forged answer, …).
* **DNS Cookies** (RFC 7873) — reuses naturally with #1's TSIG work.
* **NSID** (RFC 5001) — surface "which node answered me" for cluster
  observability.
* **Padding** (RFC 7830) — DoT/DoH privacy padding.

Why this is #3: each item is small individually; collectively they
move ExDns from "RFC 1035 + a few extras" into "current decade DNS
deployment".

## Order of recommended work

If we tackle the three tranches sequentially:

1. **TSIG first** (within tranche 1) — small, self-contained, unlocks
   secure zone transfers immediately and is a prerequisite for
   Catalog Zones and DNS UPDATE later.
2. Then **DNSSEC validation** (recursive side) — uses the same
   `:public_key` library and gives us a real reason to keep recursing
   in production.
3. Then **DNSSEC signing** — same crypto plumbing, harder operations
   story (key rollovers, NSEC vs NSEC3 chains).
4. Switch to tranche 2 — start with **Prometheus metrics** because
   they unblock observing everything we do next, then **disk
   persistence**, then **ACLs + RRL**, then **config files + hot
   reload**.
5. Then tranche 3 — **DoT** first (smallest), then **ECS**, then EDE
   / Cookies / NSID / padding as a batch, then **DoQ** when the
   Erlang QUIC ecosystem matures further.

## What we deliberately do NOT add

To keep ExDns coherent:

* No DNS load balancing / dnsdist clone — that's a different product.
* No HTTP API for zone management as a first-class feature; the
  policy chain + hot reload are the better substrate.
* No CoreDNS-style plugin DSL — we already have the policy chain
  behaviour, which is the same idea with less framework.
