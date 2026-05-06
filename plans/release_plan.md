# ExDns release plan

Production-readiness assessment + tiered hardening work to ship.

## Verdict

ExDns is a credible **evaluation / lab / closed-network** product today. Putting it on the public internet — as an authoritative public NS or as an open recursor — would expose **two critical bugs** (DNSSEC validation + cache-poisoning resistance) and a posture where most defensive controls **default off**. With ~1–3 weeks of focused work the critical defects are fixable; turning on the existing controls is mostly configuration. Multi-node clustering is fresh code and the hardest parts (split-brain, partition recovery) are untested.

## Critical — fix before any internet exposure

1. **DNSSEC validator never checks RRSIG inception/expiration**
   `lib/ex_dns/dnssec/validator.ex:62-79` runs `verify_rrset/3` and only checks (algorithm, key tag, signature). The `signature_inception` / `signature_expiration` fields are emitted into the canonical bytes (lines 290-291) but never compared against the wall clock. **An RRSIG that expired in 2010 still validates if the key signed it.** RFC 4035 §5.3.1 violation.

2. **Recursor uses `:rand.uniform/1` for outbound query IDs** — `lib/ex_dns/recursor/iterator.ex:493` — Erlang's PRNG is non-cryptographic and predictable. Combined with no qid match in `matches_question?/3` (`iterator.ex:526`), this is the classic Kaminsky surface.

3. **Compression-pointer parser has no loop guard**
   `lib/ex_dns/message.ex:365-385`: `decode_name_labels` follows compression pointers recursively with a bounds check on the offset but **no check that the pointer moves backward and no max-recursion depth**. A self-referential pointer pegs one BEAM scheduler thread per query.

## Important — fix before broad production

4. **Bearer tokens stored as plaintext** — server `lib/ex_dns/api/token_store.ex:79-91`, UI `dns_ui/lib/dns_ui/accounts.ex:152`. `chmod 0600` happens after the write.

5. **TokenStore re-reads `tokens.json` on every API request** (`token_store.ex:54`). Filesystem DoS surface, no auth-failure rate limit.

6. **TSIG has no replay cache** — `lib/ex_dns/tsig.ex:188-198`. Captured signed UPDATE replayable for 5min.

7. **Recursor cache is unbounded** — `lib/ex_dns/recursor/cache.ex`. Random-subdomain water torture OOMs the BEAM.

8. **RRL and DNS Cookies both default `enabled: false`** — `rrl.ex:158`, `cookies/post_process.ex:75`.

9. **Web UI session cookie missing `secure: true`** — `dns_ui/lib/dns_ui_web/endpoint.ex:4-9`.

10. **No brute-force throttling on UI login** — `dns_ui/lib/dns_ui/accounts.ex:82-118`.

## Worth knowing

- Token scope `--scopes "*"` broken (`auth.ex:132-133` only handles leading `*.`).
- No 0x20 case randomisation.
- NXNS bounded by `max_depth: 16` but recursion to NS targets still amplifies.
- DNSSEC algorithm policy is RFC 8624 correct.
- TSIG MAC compare is constant-time; algorithm taken from key store, not wire.
- DoT defaults TLS 1.2+1.3.
- PBKDF2 600k iterations on UI passwords matches OWASP.

## DDoS posture

| Control | Status |
|---|---|
| RRL token bucket | Implemented; **defaults off** |
| DNS Cookies (RFC 7873) | Implemented; **defaults off** |
| BADCOOKIE enforcement | Implemented; **defaults off** |
| Refuse-ANY (RFC 8482) | Implemented; opt-in |
| EDNS payload size honoured | Implemented |
| TCP idle timeout | 5s — good |
| TCP per-IP connection cap | **Not present** |
| Recursor cache size cap | **Not present** |
| max_depth on referrals | 16 — bounded |
| Source port randomisation | Implicit (OS) |
| Query ID entropy | **Non-CSPRNG** |
| 0x20 case randomisation | Not present |
| Cache poisoning: response qid match | **Not enforced** |

## Test coverage

- 1203 tests, ~24s, **one flake** (`Catalog.Subscription`).
- Well covered: wire codec, DNSSEC primitives, TSIG MAC, recursor logic, plugin framework, API auth/router.
- Untested: disk-full, network partition / split-brain, memory pressure, listener bind failure, DoT/DoH cert lifecycle, key expiry mid-flight, drain interruption, zone-file / RPZ / adlist parsers (only message decoder fuzzed).
- Claims without proportionate tests: DoT integration, DoH-over-TLS, DoQ binding, drain-with-in-flight, OpenTelemetry span emission.

## Failure-mode posture

- Graceful drain implemented; only empty-case tested.
- EKV durability OK; cluster split-brain untested.
- Catalog subscription flakes (fixture leak).
- Backup story not documented as runbook.

## Packaging / deployment

| Item | Status |
|---|---|
| `mix release` config | **Missing** |
| Hex publishability | **Not ready** — no `package` block |
| Systemd unit | **Missing** sample (sd_notify wired) |
| Dockerfile | **Missing** |
| CHANGELOG | "Unreleased" only |
| Version | `0.1.0` pre-release |
| `runtime.exs.example` | Present, comprehensive |
| CLI (`bin/exdnsctl`) | Wraps `mix exdns.ctl` |
| Operator runbooks | Guides 01–10 written. Missing: backup/restore, DR, cert renewal, EKV node loss, planned upgrade |

## Tier 1 — must fix before any internet exposure (~1–2 weeks)

- Enforce RRSIG inception/expiration in `Validator.verify_rrset/3`; tests for clock-past / clock-future / clock-within.
- Query-ID via `:crypto.strong_rand_bytes/1`; assert response qid match in iterator.
- Max-pointer-depth + visited-offset in `decode_name_labels`; fuzz test for self-referential pointer with bounded runtime.
- Hash bearer tokens at rest in `TokenStore` and `Accounts`.
- Cache token registry in `:persistent_term`, invalidate on mutation; rate-limit auth failures.
- Default RRL enabled (5 rps, slip 2). Default DNS Cookies enabled. Document off-switch.
- Bound recursor cache (`max_entries`, simple LRU).
- TSIG replay cache for UPDATE.
- `secure: true` on Phoenix session cookie; document HTTPS-fronting.

## Tier 2 — before broad production (~1–2 weeks more)

- Fix the `*` scope glob matcher.
- 0x20 case randomisation (opt-in).
- Per-IP TCP/TLS connection cap.
- ZSK/KSK signing-lag alert + signing test crossing expiry.
- Quarantine the catalog-subscription flake.
- Fuzz the zone-file parser, RPZ parser, BlackHole adlist parser.
- Cluster split-brain test using the EKV peer simulator.

## Tier 3 — ship-grade

- `mix release` config with runtime config, systemd unit, Dockerfile.
- Hex-publishable `package` block.
- Backup/restore + DR runbooks.
- Tag `0.2.0` and start release cadence.
