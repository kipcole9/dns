# Where ExDns is deficient vs. the leading DNS servers

Date: 2026-05-05 (originally) · **Updated 2026-05-05** after the
Crypto, Operational Maturity, Modern Privacy, RFC 2136 +
RPZ batches landed.

## Status update

This document was written when ExDns had **264 tests** and most
of the gap matrix below was filled with `❌`. It has since been
worked through in batches; the bulk of the original gap matrix
is now closed. **837 tests passing** as of the latest run.

The "Recommended top three" tranches are all complete:

| Original tranche | Status | Notes |
|---|---|---|
| **1. Cryptographic security: DNSSEC + TSIG** | ✅ done | Validation, signing (ZSK + KSK), TSIG sign/verify both directions, DNS Cookies, NSEC3 + opt-out, RFC 6975 algorithm signaling, RFC 8624 algorithm policy enforcement, CDS/CDNSKEY auto-publication |
| **2. Operational maturity** | ✅ done | DETS-backed persistent journal, hot reload, Prometheus + dnstap + structured logs + OpenTelemetry, transfer/notify/update/view ACLs, RRL with slip + cookie exemption, glob-expanded `:zones` config, `mix exdns.ctl` CLI, admin HTTP API, sd_notify, graceful drain |
| **3. Modern privacy & extension surface** | ✅ done | DoT, DoH (POST + GET + Cache-Control), DoQ handler (QUIC binding deferred), ECS, EDE, Padding, EDNS Keepalive |

The two showstopper-rated BIND-parity items have also landed:

* **RFC 2136 Dynamic UPDATE** — opcode 5 with per-zone ACL,
  prerequisite checking (forms 2/4/5), atomic apply with SOA
  serial bump.
* **RPZ parser** — owner-name + record-type triggers (qname,
  wildcard, rpz-ip IPv4 + IPv6) parsed into a structured
  rule set ready for plugin / policy consumption.

## Reference set

* **Authoritative:** BIND 9, Knot DNS, NSD, PowerDNS Authoritative
* **Recursive:** Unbound, BIND 9, PowerDNS Recursor, dnsmasq
* **Hybrid / load-balancer:** dnsdist, CoreDNS

## What we have today (revised)

### Authoritative + recursive core
* 26 RR types with bitstring decode/encode (incl. SVCB/HTTPS,
  CDS, CDNSKEY, all DNSSEC RRs, SSHFP, NAPTR, LOC, CAA)
* ETS-backed authoritative resolution with NXDOMAIN/NODATA,
  CNAME chasing, wildcards, NS delegation + glue, ANY,
  SOA-in-authority for negative caching
* Recursive resolution (root hints, ETS cache, iterative
  resolver, hybrid mode, stub-resolver / forwarder mode)
* Per-query views (BIND `view`-style) — split horizon,
  multi-tenant, with strict + inherit fall-through modes
* RFC 2308 negative caching (separate NXDOMAIN vs NODATA),
  RFC 9156 QNAME minimisation, RFC 8198 aggressive NSEC use

### Cryptography
* DNSSEC validation (full chain to IANA root)
* DNSSEC signing — ZSK + KSK with rollover automation,
  ECDSA P-256 + Ed25519, NSEC + NSEC3 chain construction
  (with opt-out), CDS / CDNSKEY auto-publication (RFC 7344)
* RFC 8624 algorithm policy enforcement (refuse MUST-NOTs,
  optional strict mode for NOT-RECOMMENDEDs)
* RFC 6975 DAU/DHU/N3U signaling
* TSIG sign + verify both directions, on inbound NOTIFY
  (per-zone ACL), on outbound transfers
* RFC 7873 DNS Cookies with optional BADCOOKIE enforcement

### Transports
* UDP + TCP (ThousandIsland)
* DoT (RFC 7858) on port 853
* DoH (RFC 8484) — POST + GET, Cache-Control per §5.1
* DoQ (RFC 9250) handler module — QUIC socket binding
  deferred (msquic system dep)
* Streaming AXFR over multiple TCP messages (RFC 5936 §2.2)
* IXFR with persistent (DETS) journal (RFC 1995)
* NOTIFY in both directions, with TSIG enforcement on the
  receive side

### Operational
* Hot reload — `Zone.Reload.reload_all/0` + glob-expanded
  `:zones` config (named.conf-style include)
* `mix exdns.ctl` CLI (rndc-equivalent) + `bin/exdnsctl`
  wrapper
* Admin HTTP API with bearer-token auth
* sd_notify (READY=1 / STOPPING=1 / WATCHDOG=1)
* Graceful drain (readyz flips, listeners close, in-flight
  workers complete)
* Prometheus exporter, dnstap, structured logs (logfmt),
  OpenTelemetry tracing

### Quality
* StreamData fuzz tests on the wire decoders (caught two
  real crash-on-malformed-input bugs)
* Benchee benchmark suite for codec + resolver
* RFC conformance suite citing the specific clause each
  assertion codifies
* 837 tests passing across all of the above

## Gap matrix (revised)

Items marked ✅ have landed since the original write-up.
Items marked ⚠️ are partial. Items still ❌ are the
remaining gap surface.

### Crypto

| Capability | Status | Notes |
|---|---|---|
| **DNSSEC signing** (online + offline) | ✅ | `ExDns.DNSSEC.Signer`, ECDSA P-256 + Ed25519. Online signing on every response when the zone has signing keys. |
| **DNSSEC validation** (recursive) | ✅ | `ExDns.DNSSEC.Validator` — full chain to IANA root, surfaces secure / insecure / bogus / indeterminate via the AD bit + EDE. |
| **TSIG** (RFC 8945) | ✅ | `ExDns.TSIG` — sign + verify, both directions, including outbound AXFR/SOA queries. |
| **SIG(0)** (RFC 2931) | ❌ | Still missing. Uncommon vs. TSIG; lower priority. |
| **DNS Cookies** (RFC 7873) | ✅ | `ExDns.Cookies` — server-side cookie generation + verification, optional BADCOOKIE enforcement. |
| **NSEC3 signing + opt-out** (RFC 5155) | ✅ | `ExDns.DNSSEC.NSEC3.Chain` — full chain construction, RFC 9276 opt-out support. |
| **KSK rollover with CDS/CDNSKEY** (RFC 7344) | ✅ | `ExDns.DNSSEC.Rollover` — three-phase pre-publish with auto CDS/CDNSKEY emission. |
| **Algorithm policy enforcement** (RFC 8624) | ✅ | `ExDns.DNSSEC.AlgorithmPolicy` — refuses MUST-NOT algorithms always, NOT-RECOMMENDED in `:strict` mode. |
| **Algorithm signaling** (RFC 6975) | ✅ | `ExDns.EDNSAlgorithmSignaling` — DAU/DHU/N3U codec + supported-algorithm reporter. |

### Operational maturity

| Capability | Status | Notes |
|---|---|---|
| **Persistent storage** | ✅ | DETS-backed IXFR journal (`ExDns.Zone.Journal.Storage.DETS`) survives restarts. Zone data itself reloaded from files on start. Full state snapshot to disk is a follow-up. |
| **Configuration files** | ⚠️ | Still Application env, but glob-expanded `:zones` (`["/etc/exdns/zones.d/*.zone"]`) gives BIND-`include`-equivalent muscle memory. A dedicated TOML/HCL config file is a follow-up. |
| **Hot reload** | ✅ | `ExDns.Zone.Reload.reload_all/0` re-reads every file in `:zones`. Triggerable via admin API + `mix exdns.ctl reload`. |
| **Prometheus / metrics** | ✅ | `ExDns.Metrics` — counter + distribution for query rate, latency, cache hit, RRL decisions, DNSSEC outcomes, etc. |
| **dnstap** (structured logging) | ✅ | `ExDns.Telemetry.Dnstap` — Frame Streams + protobuf encoder, file sink. |
| **Query log** | ✅ | `ExDns.Telemetry.StructuredLogger` — logfmt-style key=value lines per query. |
| **ACLs / allowlists** | ✅ | `ExDns.Transfer.ACL` (AXFR/IXFR), `ExDns.Notify.ACL` (NOTIFY), `ExDns.Update.ACL` (DDNS), `ExDns.View` (per-query). All take CIDR + optional TSIG-key gates. |
| **AXFR access control** | ✅ | `ExDns.Transfer.ACL` — default-allow when no entry, default-deny once configured. CIDR + TSIG-key gates. |
| **Response Rate Limiting** (RRL) | ✅ | `ExDns.RRL` — token-bucket per `(client_subnet, qname, qtype, response_kind)`, slip mechanism, cookie-validated bypass. |
| **Zone validation** | ⚠️ | The parser still accepts whatever a zone file says. SOA-serial monotonicity, glue check, CNAME-coexistence are follow-ups. |
| **Per-query views** (BIND `view`) | ✅ | `ExDns.View` + `ExDns.View.Storage` + `ExDns.View.Resolver` — split-horizon, multi-tenant, strict + inherit modes. |
| **RNDC-equivalent CLI** | ✅ | `mix exdns.ctl` + `bin/exdnsctl` wrapper. |
| **Health probes** | ✅ | `ExDns.Health` — `/healthz` + `/readyz` over Bandit on a dedicated port. |
| **Graceful shutdown** | ✅ | `ExDns.Drain` — readiness flips, listeners close, in-flight workers complete, DETS journal flushes. |
| **systemd integration** | ✅ | `ExDns.SystemD` — sd_notify READY/STOPPING/WATCHDOG. |

### Modern protocol features

| Capability | Status | Notes |
|---|---|---|
| **DNS-over-TLS** (DoT, RFC 7858) | ✅ | `ExDns.Listener.DoT` — TLS-wrapped TCP on port 853. |
| **DNS-over-QUIC** (DoQ, RFC 9250) | ⚠️ | `ExDns.Listener.DoQ` handler module exists; QUIC socket binding deferred (requires the platform-specific msquic library via `:quicer`). |
| **EDNS Client Subnet** (ECS, RFC 7871) | ✅ | `ExDns.EDNSClientSubnet` — full IPv4 + IPv6 codec, response-side echo with SCOPE=0. |
| **NSID** (RFC 5001) | ❌ | Still missing. Small, low-priority; a follow-up. |
| **Padding** (RFC 8467) | ✅ | `ExDns.EDNSPadding` — RFC 8467 §4.2 block padding (468-byte default), wired into DoT + DoH. |
| **Extended DNS Errors** (EDE, RFC 8914) | ✅ | `ExDns.ExtendedDNSErrors` — full IANA registry of 30 named codes, multi-EDE responses. Wired into DNSSEC outcomes + view REFUSED. |
| **Catalog zones** (RFC 9432) | ✅ | `ExDns.Zone.Catalog` (parser) + `ExDns.Zone.Catalog.Applier` (reconciler against `ExDns.Zone.Secondary`). |
| **DNS UPDATE** (RFC 2136) | ✅ | `ExDns.Update.{ACL,Prerequisites,Applier}` + opcode 5 dispatch in `Resolver.Default`. ACL-gated, atomic, SOA-serial bumping. |
| **Outbound NOTIFY** | ✅ | `ExDns.Notify` — fired automatically by `Storage.put_zone/2` on serial advance. |
| **Real IXFR** (with journal) | ✅ | `ExDns.Zone.Journal` (ETS or DETS storage) records every serial advance; `Resolver.Default` IXFR clause emits the differences sequence per RFC 1995 §4 with AXFR fallback when the journal can't satisfy. |
| **RPZ** (Response Policy Zones) | ⚠️ | `ExDns.RPZ` parser emits a structured rule set from an RPZ zone file. Runtime application (consult rules per query) is a follow-up — wires naturally into the planned plugin framework. |
| **Views / split-horizon** | ✅ | `ExDns.View` + `ExDns.View.Storage` + `ExDns.View.Resolver` — full BIND-style view selection by source IP / TSIG key. |
| **EDNS Keepalive** (RFC 7828) | ✅ | `ExDns.EDNSKeepalive` — server signals idle timeout to keepalive-aware clients. Wired into TCP/DoT. |
| **Streaming AXFR** (RFC 5936 §2.2) | ✅ | `ExDns.Zone.AxfrStream` — chunks large responses across multiple TCP messages. |
| **DoH GET** (RFC 8484 §4.1) | ✅ | `ExDns.Listener.DoH.Router` — POST + GET + Cache-Control max-age. |

### Recursive-specific (vs. Unbound)

| Capability | Status | Notes |
|---|---|---|
| **DNSSEC validation** | ✅ | Full chain to root, AD-bit, EDE annotation. |
| **QNAME minimisation** (RFC 9156) | ✅ | `ExDns.Recursor.QnameMinimisation` — opt-in. |
| **Aggressive NSEC use** (RFC 8198) | ✅ | `ExDns.DNSSEC.AggressiveNSEC` predicates wired into the iterator's lookup path. |
| **Prefetching** | ❌ | Still missing. Refresh popular records ~10% before TTL expiry. |
| **Serve stale** (RFC 8767) | ❌ | Still missing. Continue serving expired records during upstream outages. |
| **Forwarding configuration** | ✅ | `ExDns.Resolver.Forwarder` — multi-upstream stub-resolver mode with failover. Per-zone forwarding still missing (would build on the new policy framework). |
| **Negative caching** (RFC 2308) | ✅ | `ExDns.Recursor.Cache` — separate `:nodata` vs `:nxdomain` shapes, TTL bounded by `min(SOA.minimum, SOA.ttl)`. |

### High-performance / hardening

| Capability | Status | Notes |
|---|---|---|
| `SO_REUSEPORT` multi-socket scaling | ❌ | Still missing. Modern UDP servers open one socket per CPU and let the kernel hash to spread load. |
| `recvmmsg` / `sendmmsg` | ❌ | Still missing. Batched syscalls cut UDP overhead substantially. |
| Source-port randomisation | ⚠️ | Still as before — kernel-picked port (0). |
| Refuse `ANY` (RFC 8482) | ❌ | Still missing. We answer ANY fully — useful for our own admins, dangerous on the public internet (amplification). |
| Fuzz testing | ✅ | StreamData property tests on `ExDns.Message.decode/1` (caught two real crash bugs). |
| Benchmark suite | ✅ | `bench/wire_codec.exs` + `bench/resolver.exs` via Benchee. |

## Remaining gaps (post-update)

The original three tranches + the two BIND-parity showstoppers
(RFC 2136 + RPZ parser) are all complete. What's left, ordered
by impact:

### Tier A — operator-visible quality

| Gap | Effort | Why it matters |
|---|---|---|
| **Refuse-`ANY` minimal-response mode (RFC 8482)** | small | We answer ANY queries fully today. On the public internet this is a DNS amplification vector — a 50-byte query returns multi-KB. Add a config flag that returns a single synthesized HINFO per RFC 8482. |
| **Zone validation on load** | small | SOA-serial monotonicity, glue-record presence, CNAME-coexistence (CNAME and any other type at the same name is a fault), DNSSEC signature freshness. Catch operator typos before they hit the wire. |
| **NSID** (RFC 5001) | trivial | Identify which cluster node answered. Useful for ops triage. |
| **Real config file** (TOML or Elixir-data) | medium | Application env is fine for tests but operators expect a `/etc/exdns/exdns.conf`. Today we have glob-expanded `:zones` + per-feature env keys; a unified config file would tie them together. |
| **RPZ runtime application** | medium | Parser is in place. Runtime needs a per-query lookup that consults the rule set and applies the action — naturally fits the planned plugin framework. |

### Tier B — recursive-side performance + privacy

| Gap | Effort | Why it matters |
|---|---|---|
| **Prefetching** | medium | Refresh popular records ~10% before TTL expiry so common lookups never block. Big latency win for high-traffic resolvers. |
| **Serve stale** (RFC 8767) | medium | Continue serving expired records while upstream is unreachable. Standard practice in modern resolvers. |
| **Per-zone forwarding** | small | Today's forwarder mode is global. Per-zone routing (`forward only` for some zones, recurse for others) would build on the policy framework. |

### Tier C — high-performance hardening

| Gap | Effort | Why it matters |
|---|---|---|
| **`SO_REUSEPORT` per-CPU sockets** | medium | Standard pattern for high-rate UDP servers. `:gen_udp.open` already supports it on Linux/BSD; just needs the listener supervisor to spawn N per-CPU. |
| **`recvmmsg` / `sendmmsg`** | large | Batched syscalls. Erlang's NIF surface for this is non-trivial; would need a small NIF or wait for OTP support. |
| **Source-port reseeding** | trivial | Kernel-picked ephemeral port already gives entropy, but a periodic refresh would harden against long-running observation. |

### Tier D — protocol surface gaps

| Gap | Effort | Why it matters |
|---|---|---|
| **DoQ socket binding** (`:quicer` integration) | medium | Handler module is ready; just needs the QUIC server. `:quicer` brings msquic as a system dep — defer until a wider audience asks. |
| **SIG(0)** (RFC 2931) | medium | TSIG alternative using DNSSEC keys. Uncommon in practice. |
| **Catalog-zone subscription state machine** | medium | Catalog parser + applier are in place. The polling state machine (watch the catalog primary's SOA, re-apply on serial change) is the missing runtime piece. |

## What we deliberately do NOT add

To keep ExDns coherent:

* No DNS load balancing / dnsdist clone — that's a different product.
* No HTTP API for zone management as a first-class feature; the
  policy chain + hot reload are the better substrate.
* No CoreDNS-style plugin DSL — we already have the policy chain
  behaviour, which is the same idea with less framework.
