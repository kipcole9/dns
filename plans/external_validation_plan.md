# External validation plan

A staged plan to validate the production-readiness work
(Tier 1 + Tier 2 + Tier 3) against the wider internet
**before** opening port 53 to the public.

## Scope

This plan covers external validation only — third-party
tools, online services, and adversarial review run from
outside our network against the deployed nameservers. It
assumes the server has been deployed per
[guides/04-delegating-your-domain.md](../guides/04-delegating-your-domain.md)
on a publicly-routable host with a real domain.

Out of scope:

* Internal unit / integration testing — already covered by
  the test suite (1249 tests, 10 properties, 128 doctests).
* Code review — covered by the audit at
  [release_plan.md](release_plan.md).
* Performance benchmarking beyond DDoS-resistance bounds.

## Staging vs production

Every step in this plan runs first against a **staging
nameserver** that's a clone of production:

* Same release tarball.
* Same `runtime.exs`.
* Different domain (e.g. `staging.yourdomain.com`).
* Different IP, on the same upstream as production.

Only after staging passes do we run the same steps against
production. The drill matters as much as the result —
operators should know the dashboards before they need them.

## Stage 1 — Delegation, glue, DNSSEC chain

**Goal**: confirm the parent zone (`.com`, `.uk`, etc) sees
the right NS + glue + DS, and validating resolvers walk the
chain cleanly.

**Tools**:

* [Zonemaster](https://zonemaster.net) — IIS / AFNIC joint
  project. Comprehensive zone-delegation + glue + DNSSEC +
  reachability + EDNS conformance.
* [DNSViz](https://dnsviz.net) — visual chain-of-trust
  graph from root → your zone. Catches glue mismatches,
  missing DS, expired RRSIGs, algorithm rollover gaps.
* [DNSSEC Analyzer](https://dnssec-analyzer.verisignlabs.com)
  — Verisign's view, useful as a cross-check to DNSViz.
* [intoDNS](https://intodns.com) — quick delegation / glue
  / SOA sanity.

**Pass criteria**:

* Zonemaster: zero errors. Warnings reviewed individually
  and either fixed or documented as accepted risk.
* DNSViz: every link green. No red triangles, no orange
  question marks.
* DNSSEC Analyzer: matches DNSViz.
* intoDNS: parent NS records match what we publish.

**Cadence**: every change to NS records, glue, DNSKEY,
DS. Automate post-change with a CI cron that hits the
Zonemaster JSON API and alerts on regression.

**Owner**: zone admin.

**Estimated time**: 30 min initial setup + 5 min per
re-check.

## Stage 2 — TLS posture for DoT and DoH

**Goal**: confirm the TLS configuration (T1.9 + listener
defaults) presents a current cipher suite, valid chain,
and OCSP / HSTS where applicable.

**Tools**:

* [SSL Labs](https://ssllabs.com/ssltest/) — covers the
  DoH endpoint on port 443. Public-facing only.
* [CryptCheck](https://cryptcheck.fr) — supports DoT
  explicitly via `_853._tcp.<host>`. The right tool for
  port 853.
* `testssl.sh` ([github.com/drwetter/testssl.sh](https://github.com/drwetter/testssl.sh))
  — self-hosted CLI alternative to SSL Labs. Run it from
  a host outside our network.

**Pass criteria**:

* SSL Labs: grade A or higher. No `BAD_CERT`, no expired
  intermediate, OCSP stapling present.
* CryptCheck: green across the board for DoT.
* testssl.sh: no `RED` findings. `YELLOW` reviewed.
* TLS 1.2 + 1.3 only. No SSLv3 / TLS 1.0 / TLS 1.1.
* Cert lifetime > 30 days at time of test.

**Cadence**: monthly. Plus immediately after every cert
renewal (see [tls-certificate-renewal.md](../guides/runbooks/tls-certificate-renewal.md)).

**Owner**: ops on-call.

**Estimated time**: 10 min per endpoint.

## Stage 3 — Cache-poisoning posture (T1.2 verification)

**Goal**: confirm the recursor's outbound-query entropy
(qid via CSPRNG, source-port randomisation) is good
enough to defeat off-path injection.

**Tools**:

* [GRC DNS Spoofability Test](https://grc.com/dns/dns.htm)
  — Steve Gibson's tool. Crusty UI, but it does what it
  says: bombards the recursor with queries and analyses
  the qid + source-port distributions.
* [DNS-OARC's `ent`](https://www.dns-oarc.net/tools/ent)
  — entropy tool. Self-host. More rigorous statistical
  analysis than GRC.

**Pass criteria**:

* GRC: "EXCELLENT" rating for both transaction ID and
  source port. Anything less indicates the OS isn't
  randomising ports the way we expect.
* `ent`: chi-square test passes for both qid and source
  port at p > 0.01.

**Cadence**: once at launch. Re-run after any change to
the recursor or BEAM/OS upgrade that might affect PRNG
behaviour.

**Owner**: developer.

**Estimated time**: 30 min including `ent` setup.

**Important**: GRC's tool needs the recursor to query
*outbound* on its behalf. That means the recursor must be
configured to recurse for the test machine's IP, OR you
test from a machine that the recursor will recurse for.

## Stage 4 — Public-internet surface scan

**Goal**: confirm only the ports we mean to expose are
reachable. Specifically that admin API (9571), health
(9572), metrics (9573), and EKV peer port are bound to
loopback or to a private network — never to the public
internet.

**Tools**:

* [Shodan](https://shodan.io) — search by our public IPs.
  Free tier shows all open ports + service banners.
* [Censys](https://censys.io) — same idea, often more
  current. Includes DNSSEC analysis.
* `nmap -p- <public-ip>` from a host outside our network.
  Sanity-check Shodan/Censys.

**Pass criteria**:

* Shodan: only 53/UDP, 53/TCP, 853/TCP, 443/TCP visible.
  No 9571, 9572, 9573, EKV peer port (default 9300+),
  no SSH, no anything else.
* Censys: same.
* nmap: same.

**Cadence**: weekly cron on Shodan API. Manual after every
firewall / network change.

**Owner**: ops on-call.

**Estimated time**: 15 min initial baseline + 5 min weekly
review.

**If a port we didn't intend to expose shows up**: stop
the rollout. The firewall is wrong, the bind address is
wrong, or someone overrode runtime.exs. Investigate before
moving on.

## Stage 5 — Load + DDoS-resistance verification

**Goal**: confirm the abuse-mitigation work (T1.6 RRL,
T1.7 recursor cache cap, T1.8 TSIG replay cache, T2.3 per-
IP TCP cap) actually engages under load and the BEAM
doesn't melt.

**Tools**:

* [`dnsperf`](https://www.dns-oarc.net/tools/dnsperf) —
  steady-state QPS measurement. Self-host.
* [`resperf`](https://www.dns-oarc.net/tools/dnsperf) —
  ramp until SERVFAIL. Same package.
* [`drool`](https://www.dns-oarc.net/tools/drool) —
  replay captured traffic at scale.

**Test matrix**:

| Test | Expected outcome |
|---|---|
| `dnsperf` 1k QPS, mixed authoritative answers | All `NOERROR` / `NXDOMAIN`. No SERVFAIL. p95 latency < 5ms. |
| `dnsperf` 1k QPS from a single source IP | RRL kicks in. Per-IP rate caps to ~5 rps (T1.6 default). Slip mechanism causes 1 in N to come back as a TC=1 truncated response. |
| `resperf` ramp to 50k QPS | Server saturates somewhere; latency rises but no crash. CPU/RAM stay bounded. |
| Random-subdomain water-torture (50k unique qnames) | Recursor cache holds at `max_entries: 100_000` (T1.7). No OOM. |
| 100 concurrent TCP connections from one IP | First 64 succeed; 65th onwards refused with log line "per-IP cap" (T2.3). |
| Captured AXFR replayed within fudge window | First succeeds, subsequent attempts return TSIG `:replay` (T1.8). |

**Pass criteria**:

* No BEAM crashes during any test.
* No SERVFAIL on any well-formed query (excluding the
  intentionally-rate-limited ones).
* Memory growth bounded — no monotonic increase under
  steady load.
* Per-test expected outcome above is observed.

**Cadence**: at launch, then quarterly. Re-run after any
RRL / cookie / cache-cap config change.

**Owner**: developer + ops together.

**Estimated time**: 1 day initial setup + 4 hours per
quarterly run.

**Watch out**: DNS-OARC tools tend to require source-IP
spoofing for realistic distributions. Run from a network
that allows it, or use a test rig with many real source
addresses (a Kubernetes job per source is one pattern).

## Stage 6 — EDNS / RFC conformance

**Goal**: confirm the server doesn't trip on common EDNS
edge cases that have caused real outages in deployed BIND
/ Knot setups.

**Tools**:

* [DNS Flag Day testers](https://dnsflagday.net) — single
  page, ~1 minute. Tests EDNS0 + DO bit + cookie + NSID +
  large response handling.
* `dig +bufsize=4096 +dnssec` — manual probe of large
  signed responses.

**Pass criteria**:

* DNS Flag Day: every check passes.
* Large signed responses (>1232 bytes) either fit in the
  EDNS buffer or trigger TC=1 + TCP fallback; never
  silently truncated.

**Cadence**: at launch + after every Tier 2 / Tier 3 of
release.

**Owner**: developer.

**Estimated time**: 5 min.

## Stage 7 — Adversarial review (optional, before public launch)

**Goal**: get human eyes on the deployment that aren't on
the team.

**Three paths, in order of cost**:

1. **Bring-your-own security engineer** — hire for a quarter,
   point them at the codebase + the deployed system. Cheapest,
   deepest. ~$25k–$40k for a 12-week engagement.

2. **Bug-bounty platform** — set scope (DNS infrastructure +
   admin API), set a reward table ($500 low / $5k high /
   $20k critical), open or invite-only. Effective for 2–4 weeks
   then signal-to-noise drops. HackerOne, Bugcrowd, Intigriti.

3. **Specialist DNS-aware pen-test firm** — NCC Group, Trail
   of Bits, Cure53. ~$30k–$150k for a 1–4 week engagement
   with a deliverable report. The right choice if a regulator
   wants to see one.

**Pass criteria**:

* Every finding triaged within 5 business days.
* Critical / high findings fixed before public launch.
* Medium findings on a 30-day SLA.
* Low / info findings on a 90-day SLA or accepted-risk doc.

**Cadence**: at major version (1.0, 2.0). After every
significant attack-surface change (new transport, new
public endpoint, new auth flow).

**Owner**: engineering lead + security lead together.

**Estimated time**: 4–12 weeks elapsed depending on path.

## Summary — minimum gate for "open port 53 to the internet"

These six stages must pass before flipping the firewall:

| Stage | Tool / artefact | Owner |
|---|---|---|
| 1 — Delegation + DNSSEC | Zonemaster + DNSViz green | Zone admin |
| 2 — TLS posture | SSL Labs A; CryptCheck green | Ops |
| 3 — Cache-poisoning posture | GRC EXCELLENT | Developer |
| 4 — Surface scan | Shodan shows only 53/853/443 | Ops |
| 5 — Load resistance | dnsperf at 1k QPS clean; resperf doesn't crash | Dev + ops |
| 6 — EDNS conformance | DNS Flag Day green | Developer |

Stage 7 (adversarial review) is recommended for any
production deployment where a real adversary cares; it's
not a gate for evaluation / SOHO use.

## Tooling we recommend self-hosting long-term

The ad-hoc external services above are good for one-shot
checks. For ongoing visibility, host these on our side:

* **dnsperf / resperf** — quarterly load runs.
* **testssl.sh** — weekly cron against DoT + DoH.
* **Zonemaster CLI** — daily cron against every zone we
  serve, alert on regression.
* **Shodan API watcher** — daily diff of our public IPs'
  open-port set.

All four can be wired into the existing Prometheus +
Alertmanager stack from
[guides/10-monitoring-and-observability.md](../guides/10-monitoring-and-observability.md).

## Reporting template

For each stage, the operator captures:

```
Stage:   <1–7>
Date:    <UTC>
Tool:    <name + version>
Target:  <staging | production>
Result:  <pass / fail / partial>
Notes:   <link to artefact / screenshot / report>
Action:  <none | follow-up ticket #>
```

Store under `var/validation/` in your ops repo (not the
ExDns source tree). Six months of history is plenty.

## What we are NOT testing externally

These remain code-review / internal-test concerns, not
addressable by online services:

* RRSIG inception/expiration enforcement (T1.1) — needs
  clock-controlled tests; covered by `validator_test.exs`.
* TSIG replay rejection (T1.8) — needs paired sender;
  covered by `update/tsig_test.exs`.
* Compression-pointer loop guard (T1.3) — needs crafted
  packet; covered by `message_test.exs`.
* Bearer-token plaintext at rest (T1.4 / T1.10) — needs
  filesystem inspection on the host; covered by
  `token_store_test.exs` / `accounts_test.exs`.
* Zone-file parser robustness (T2.6) — covered by
  `zone_file_fuzz_test.exs`.

If something goes wrong in any of those, our internal
suite should catch it before deployment. The external
plan is the second line of defence, not the first.
