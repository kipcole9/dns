# Fly.io initial deployment plan

A focused plan to take the Tier 1 + Tier 2 + Tier 3
hardened build live on Fly.io as the authoritative
nameserver for a single test domain registered through
Cloudflare.

## Goal of this iteration

Stand up **one** ExDns instance on Fly that:

* Holds the master copy of one zone (the test domain).
* Answers public queries on UDP/53 + TCP/53.
* Is exposed to the wider internet (so it can be probed
  with the [external validation plan](external_validation_plan.md)).
* Costs less than US$10 / month while we validate.

What we are **not** doing in this iteration:

* DoT / DoH / DoQ — single-port-53 setup first; TLS
  layers come once the basics work.
* DNSSEC signing — guide 07's recipe ports cleanly to
  Fly but is intentionally a separate step to keep
  rollback simple.
* Multi-node cluster — `cluster_size: 1`. Two-node and
  three-node Fly deployments come after this one is
  proven.
* Web UI — `dns_ui` deploys identically (it's a separate
  Fly app pointed at the server's API), but isn't on
  this critical path.

## Prerequisites

Before touching Fly:

| Prerequisite | How to verify |
|---|---|
| Tier 1 + 2 + 3 work merged | `git log` shows the security commits + `mix release` config in `mix.exs` |
| Server suite green | `mix test` → 1249 passing |
| Server release tarball builds | `MIX_ENV=prod mix release ex_dns --overwrite` succeeds |
| Server Dockerfile builds locally | `docker build -t exdns-test .` succeeds |
| `flyctl` installed + logged in | `fly auth whoami` returns the right org |
| Domain registered at Cloudflare | Visible under "Domain Registration" in the dashboard |
| Cloudflare API token (DNS edit) | Created at [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens), scoped to the test zone only |
| Payment method on Fly | Required for dedicated IPv4, which we need for UDP |

If any row is missing, fix it before the next section.

## §1 — Fly app + persistent volume

ExDns needs a single Fly app with one machine and one
volume. The volume holds:

* `/var/lib/exdns/ekv/` — EKV data dir (zone state,
  plugin registry, TSIG keys, DNSSEC keys, BlackHole).
* `/var/lib/exdns/snapshot.bin` — belt-and-braces zone
  snapshot.
* `/var/lib/exdns/tokens.json` — bearer-token registry
  (hashed at rest per T1.4).

Pick a region close to where probing will originate (the
[external validation plan](external_validation_plan.md)
runs from where you sit). For most readers that's `lhr`
(London), `iad` (Virginia), or `syd` (Sydney). Get the
list with `fly platform regions`.

```bash
# 1. Create the app. The app name is the public
#    Fly hostname (`<name>.fly.dev`); pick something that
#    won't embarrass you.
fly apps create exdns-test --org personal

# 2. Allocate a 3 GB volume in the chosen region.
#    EKV's working set for a single small zone fits in
#    < 100 MB; 3 GB gives plenty of headroom for query log
#    + future zone growth + future BlackHole adlists.
fly volumes create exdns_state \
  --app exdns-test \
  --region lhr \
  --size 3 \
  --yes
```

Verify:

```bash
fly volumes list --app exdns-test
# id              state   name           size  region   …
# vol_xxxxxxxx    created exdns_state    3 GB  lhr      …
```

**Cost reality**: Fly's volume pricing as of writing is
roughly $0.15 / GB / month — 3 GB ≈ $0.45 / month. Verify
on [fly.io/docs/about/pricing](https://fly.io/docs/about/pricing/)
before allocating; pricing tiers change.

## §2 — Networking: UDP requires a dedicated IPv4

DNS is fundamentally a UDP protocol. Fly supports UDP, but
**UDP requires a dedicated IPv4 address** — shared IPv4
won't deliver UDP packets to your app.

```bash
# 1. Allocate a dedicated IPv4. This is a paid resource
#    (~$2 / month at time of writing).
fly ips allocate-v4 --app exdns-test
# Allocated v4 a.b.c.d  ($X.YZ / month)

# 2. Allocate an IPv6 too. Free and required for AAAA
#    delegation if you want IPv6 clients.
fly ips allocate-v6 --app exdns-test

# 3. Verify.
fly ips list --app exdns-test
# TYPE    ADDRESS              REGION    CREATED AT
# v4      a.b.c.d              global    …
# v6      2a09:8280:1::a:bcde  global    …
```

Note these addresses — they are the values Cloudflare's
glue records will point at (see §6).

### Ports we expose in this iteration

| Port | Proto | Purpose |
|---|---|---|
| 53 | UDP | DNS queries (the main event) |
| 53 | TCP | DNS queries > 512 bytes, AXFR / IXFR fallback |

### Ports we do **not** expose externally

| Port | Why |
|---|---|
| 9571 | Admin API — bind to localhost only (use `fly ssh` to manage) |
| 9572 | Health probe — Fly's health check reads this internally |
| 9573 | Prometheus metrics — internal only |
| 853 | DoT — postponed until basics work |
| 443 | DoH — postponed until basics work |

Fly's firewall is "everything is closed unless declared
in `fly.toml`", so omitting them from `[[services]]` is
all the protection we need. Stage 4 of the validation
plan will confirm this externally with Shodan.

## §3 — Secrets + runtime.exs for Fly

The release reads `runtime.exs` at boot. We bake a
Fly-specific one into the image at
`/opt/exdns/etc/runtime.exs` and point at it via
`EXDNS_RUNTIME_CONFIG`. Anything that varies per
deployment (NSID identifier, public IP, zone list) goes
into Fly secrets.

### Secrets

```bash
# RELEASE_COOKIE — required by mix releases. Generate
# fresh; never commit.
fly secrets set --app exdns-test \
  RELEASE_COOKIE="$(openssl rand -hex 32)"

# EXDNS_PUBLIC_NS — the FQDN the world sees us as. Goes
# into the NSID OPT response, the SOA mname, and the NS
# records served from inside the zone.
fly secrets set --app exdns-test \
  EXDNS_PUBLIC_NS="ns1.<your-test-domain>"

# EXDNS_NSID — operator identifier echoed back in
# replies that ask for NSID (RFC 5001). Useful in dig
# output for confirming "yes, this answer came from MY
# server, not a Cloudflare leftover".
fly secrets set --app exdns-test \
  EXDNS_NSID="exdns-test-fly-lhr"
```

### Runtime config baked into the image

Save as `contrib/fly/runtime.exs` in the repo (new file;
it lives alongside the systemd unit):

```elixir
import Config

# Bind on all interfaces — Fly's networking layer
# delivers public traffic to 0.0.0.0:53.
config :ex_dns,
  listener_port: 53,
  zones: ["/etc/exdns/zones.d/*.zone"]

# Identity — sourced from Fly secrets at boot.
config :ex_dns, :nsid,
  enabled: true,
  identifier: System.get_env("EXDNS_NSID", "exdns")

# Single-node EKV. Volume-backed; survives machine
# restart. cluster_size: 1 — multi-node comes later.
config :ex_dns, :ekv,
  enabled: true,
  data_dir: "/var/lib/exdns/ekv",
  cluster_size: 1,
  mode: :member

# Snapshot — belt and braces for runtime mutations.
config :ex_dns, :zone_snapshot,
  enabled: true,
  path: "/var/lib/exdns/snapshot.bin"

# Admin API — loopback only on the Fly machine. Reach
# via `fly ssh console -C "/opt/exdns/bin/exdnsctl …"`.
config :ex_dns, :api,
  enabled: true,
  port: 9571,
  bind: {127, 0, 0, 1},
  token_path: "/var/lib/exdns/tokens.json"

# Health probe on a separate port — Fly's TCP health
# check hits this.
config :ex_dns, :health,
  enabled: true,
  port: 9572

# Tier 1 + Tier 2 abuse mitigation defaults — explicit so
# operators can see them in the deployed config.
config :ex_dns, :rrl,
  enabled: true,
  responses_per_second: 5,
  burst: 25,
  slip: 2

config :ex_dns, :cookies, enabled: true, enforce: false

config :ex_dns, :api_auth_throttle, enabled: true

config :ex_dns, :per_ip_cap, enabled: true, max_per_ip: 64

# Recursion off — we are authoritative-only for this
# iteration. (See guide 03 for when to flip this.)
config :ex_dns, recursion: false
```

Add the file path to the server `Dockerfile`'s `COPY`
list and set `ENV EXDNS_RUNTIME_CONFIG=/opt/exdns/etc/runtime.exs`
(see §5).

## §4 — fly.toml + Dockerfile adjustments

### `fly.toml`

Save at the repo root (committed; no secrets in here):

```toml
app = "exdns-test"
primary_region = "lhr"

[build]
  dockerfile = "Dockerfile"

[env]
  PHX_HOST = "ns1.<your-test-domain>"
  EXDNS_RUNTIME_CONFIG = "/opt/exdns/etc/runtime.exs"

[[mounts]]
  source = "exdns_state"
  destination = "/var/lib/exdns"

# DNS over UDP — requires a dedicated v4 (allocated in §2).
[[services]]
  protocol = "udp"
  internal_port = 53

  [[services.ports]]
    port = 53

# DNS over TCP — for >512-byte responses + AXFR/IXFR.
[[services]]
  protocol = "tcp"
  internal_port = 53

  [[services.ports]]
    port = 53

  # Aggressive idle close protects against slow-loris.
  # Matches the 5s timeout in `lib/ex_dns/listener/tcp_listener.ex`.
  [services.concurrency]
    type = "connections"
    hard_limit = 1024
    soft_limit = 800

# Fly health check — readiness probe at /readyz.
[[services.tcp_checks]]
  interval = "15s"
  timeout = "3s"
  grace_period = "10s"
  port = 9572

[[vm]]
  size = "shared-cpu-1x"
  memory = "512mb"
```

### Dockerfile delta

The repo's existing `Dockerfile` (T3.3) already builds a
release tarball + drops it at `/opt/exdns`. For Fly we
need two extra lines: copy the runtime config and point
the env var at it.

Add to the runtime stage (after the `COPY --from=builder`
line):

```dockerfile
COPY contrib/fly/runtime.exs /opt/exdns/etc/runtime.exs
ENV EXDNS_RUNTIME_CONFIG=/opt/exdns/etc/runtime.exs
```

The Fly machine runs as root by default; the existing
`USER exdns:exdns` directive in our Dockerfile keeps the
process unprivileged. The `setcap` line in T3.3 already
permits port-53 binding without root.

### Initial zone file

Create `contrib/fly/zones.d/yourdomain.com.zone` (commit
this — it's the canonical source). Adjust to your test
domain and IPs:

```dns
$TTL 3600
$ORIGIN yourdomain.com.
@           IN  SOA   ns1.yourdomain.com. hostmaster.yourdomain.com. (
                 2026010101 ; serial
                 7200       ; refresh
                 3600       ; retry
                 1209600    ; expire
                 3600 )     ; minimum

            IN  NS    ns1.yourdomain.com.

; Glue — points at the Fly app's dedicated v4 (from §2).
ns1         IN  A     a.b.c.d

; Demo records.
@           IN  A     a.b.c.d
www         IN  A     a.b.c.d
```

Add a Dockerfile line to copy zones into the image:

```dockerfile
COPY contrib/fly/zones.d /etc/exdns/zones.d
```

Editing zones means rebuilding the image. That's fine
for this iteration — runtime mutations via the API still
land in the EKV state on the volume; the file copy is
just the bootstrap on first boot of a fresh volume.

## §5 — Cloudflare delegation

Walk through [guide 04](../guides/04-delegating-your-domain.md)
end-to-end against the test domain. The mechanics are the
same; the only Fly-specific bit is the IP that goes into
the glue record.

Order matters — **register glue first, change NS second**.

### 5a — Register glue at Cloudflare

In the Cloudflare dashboard:

1. Open the test domain.
2. **DNS** → **Records** → take a screenshot of every
   existing record (we're about to remove them by moving
   off Cloudflare DNS).
3. **DNS** → **Custom Nameservers** (sometimes labelled
   "Child Nameservers" or "Register Glue Records").
4. Add: hostname `ns1.<your-test-domain>` → IPv4 = the
   dedicated v4 from §2 (`a.b.c.d`).
5. (Optional) Add the same hostname → IPv6 = the v6 from
   §2.
6. Save. Cloudflare submits to Verisign within a few
   minutes.

Verify the glue is propagating:

```bash
dig @a.gtld-servers.net ns1.<your-test-domain> A
# Should return your Fly v4.
```

If it doesn't return after 30 minutes, the registration
in step 3 didn't go through. Re-check the dashboard.

### 5b — Wait for ExDns to be running before changing NS

**Don't change the authoritative NS at Cloudflare yet.**
Until ExDns answers on the Fly v4, flipping NS would
black-hole the domain.

Order:

1. (§6) Deploy the app.
2. (§7) Verify it answers correctly from outside.
3. *Then* come back here and do 5c.

### 5c — Change the authoritative NS at Cloudflare

Once §7 confirms ExDns responds:

1. **Domain Registration** → **Nameservers**.
2. Change from Cloudflare's defaults
   (`xxx.ns.cloudflare.com`) to: `ns1.<your-test-domain>`.
3. Save.
4. Cloudflare confirms with a banner; the parent zone
   change goes to Verisign; resolvers see the new NS
   within a few hours (in practice).

This is **the cut-over**. Any DNS lookup for your test
domain from now on hits ExDns. If something's wrong,
flip the NS back at Cloudflare and investigate.

### 5d — Cloudflare DNS proxy gotcha

Make sure you're **not using** Cloudflare's `Proxied`
toggle on any record — that's only for Cloudflare-hosted
DNS, and we're moving off it. Disable proxying on every
existing record first; deletion of those records happens
naturally when the NS change takes effect.

## §6 — Deploy + smoke test

### Deploy

```bash
cd ~/Development/dns
fly deploy --app exdns-test --remote-only
```

`--remote-only` builds the image on Fly's builders rather
than locally; useful for the EKV NIF compile because the
target Linux libc matches the runtime. Watch the build
log; expect 3–5 minutes for a cold build, < 1 min for a
cached rebuild.

### Wait for healthy

```bash
fly status --app exdns-test
# Should show: state=started, health checks=passing
```

Tail the log until you see EKV ready:

```bash
fly logs --app exdns-test
# Look for:
#   [EKV :ex_dns] started (shards=8)
#   [EKV ex_dns] startup quorum reached after Nms
#   Starting UDP server for :inet on address 0.0.0.0 and port 53
```

If anything looks wrong, `fly ssh console --app exdns-test`
gets you a shell on the machine.

### Smoke test from outside the Fly network

From your laptop, NOT through Fly:

```bash
PUBLIC_IP=a.b.c.d   # the Fly v4 from §2

# 1. Authoritative SOA — must come back with AA=1.
dig @${PUBLIC_IP} <your-test-domain> SOA
# flags: qr aa rd ; status: NOERROR

# 2. NS records served from inside the zone.
dig @${PUBLIC_IP} <your-test-domain> NS +short
# ns1.<your-test-domain>.

# 3. Glue lookup.
dig @${PUBLIC_IP} ns1.<your-test-domain> A +short
# a.b.c.d

# 4. NSID echoes back our identifier.
dig @${PUBLIC_IP} <your-test-domain> SOA +nsid
# NSID: 65 78 64 6e 73 2d 74 65 73 74 2d 66 6c 79 2d 6c 68 72  ("exdns-test-fly-lhr")

# 5. NXDOMAIN with AA=1.
dig @${PUBLIC_IP} nope.<your-test-domain> A
# status: NXDOMAIN, flags: qr aa

# 6. TCP works (large response or +tcp).
dig @${PUBLIC_IP} <your-test-domain> SOA +tcp
```

If any of the six fails, **don't change the NS at
Cloudflare** (§5c). Investigate first.

### Pass criteria for smoke test

* All six dig commands return the documented result.
* `fly logs` shows no `error=…` lines during the queries.
* `fly ssh console -C "/opt/exdns/bin/exdnsctl status"`
  reports `ready: true`.

Once all green, go back to §5c and flip the NS at
Cloudflare.

## §7 — Post-deploy external validation

After §5c (NS flipped at Cloudflare), wait one parent-TTL
(.com is ≈ 24h, but resolvers usually pick up within an
hour). Then walk through the relevant stages of the
[external validation plan](external_validation_plan.md).

Stages applicable to this iteration (DoT/DoH skipped, no
DNSSEC yet):

| Validation stage | Tool | Expected |
|---|---|---|
| 1 — Delegation | [Zonemaster](https://zonemaster.net) on the test domain | Zero errors |
| 1 — Glue propagation | `dig @a.gtld-servers.net <domain> NS` | Returns `ns1.<domain>` with glue |
| 4 — Surface scan | [Shodan](https://shodan.io) on the Fly v4 | Only 53/UDP + 53/TCP visible |
| 5 — Load resistance | `dnsperf -s <fly-v4> -d queryfile -l 60 -Q 1000` from a separate VPS | No SERVFAIL; RRL kicks in on per-IP rate |
| 6 — EDNS conformance | [DNS Flag Day](https://dnsflagday.net) | All checks green |

Stages 2 (TLS posture), 3 (cache-poisoning posture —
recursor-specific), and 7 (adversarial review) wait for
later iterations.

### What "pass" looks like

Capture the timestamp + tool + result for each row in your
ops log. Sample:

```
2026-05-15T09:30:00Z  Zonemaster <test-domain>     PASS  zero errors
2026-05-15T09:35:00Z  Shodan a.b.c.d              PASS  only 53/udp + 53/tcp
2026-05-15T09:50:00Z  dnsperf 1k QPS, 60s         PASS  0 SERVFAIL, RRL slip observed
2026-05-15T09:55:00Z  DNS Flag Day                PASS  all green
```

If any row fails, hold further changes until it's resolved.

## §8 — Ongoing operations on Fly

### Day-to-day

| Task | Command |
|---|---|
| Tail logs | `fly logs --app exdns-test` |
| Open a shell on the machine | `fly ssh console --app exdns-test` |
| Run admin CLI | `fly ssh console --app exdns-test -C "/opt/exdns/bin/exdnsctl status"` |
| Issue an API token | `fly ssh console -C "/opt/exdns/bin/exdnsctl token issue --role zone_admin --scopes '*'"` |
| Watch metrics | `fly ssh console -C "curl -sS http://127.0.0.1:9573/metrics"` |
| Force a zone reload from disk | `fly ssh console -C "/opt/exdns/bin/exdnsctl zone reload <apex>"` |
| Scale resources | `fly scale memory 1024 --app exdns-test` |
| Restart the machine (drains gracefully) | `fly machine restart --app exdns-test` |

### Backups

The volume holds the entire authoritative state. Fly
volumes already snapshot daily; the [backup-and-restore
runbook](../guides/runbooks/backup-and-restore.md) augments
this with operator-controlled exports:

```bash
# Pull a tarball of /var/lib/exdns to your laptop.
fly ssh console --app exdns-test -C \
  'tar --use-compress-program=zstd -cf - -C /var/lib/exdns .' \
  > "exdns-backup-$(date -u +%Y-%m-%dT%H-%M-%SZ).tar.zst"
```

Schedule weekly until the deployment matures, then daily.

### Cost estimate

| Line item | Approx monthly |
|---|---|
| `shared-cpu-1x` machine (always-on) | $1.94 |
| 512 MB RAM | included |
| 3 GB volume | $0.45 |
| Dedicated IPv4 | $2.00 |
| IPv6 | $0.00 |
| Outbound bandwidth (low traffic) | < $1 |
| **Total** | **≈ $5–7 / month** |

Numbers from Fly's pricing page at time of writing —
**verify before you provision**; pricing changes. If the
machine moves to `auto_stop = true` the line drops to
~$3 / month, but DNS is the wrong workload for cold-start
machines (the first query after stop pays the boot
penalty + DNSSEC validation cache miss).

### Monitoring

The Prometheus metrics endpoint at `:9573/metrics` is
private to the machine. Two integration paths:

1. **Fly's Grafana** (free tier) — point a Prometheus
   scrape at the machine's internal address. Setup at
   [fly.io/docs/metrics-and-logs/metrics/](https://fly.io/docs/metrics-and-logs/metrics/).
2. **External Prometheus** (your existing observability
   stack) — open `:9573` on the machine to a private
   network only, scrape from there.

Pick (1) for the test iteration; switch to (2) if/when
this graduates to a serious deployment.

## §9 — Graduation path

Once the single-NS test domain has been answering cleanly
for two weeks with no incidents, here's the deliberate
sequence to take it the rest of the way to production.
**Do one step at a time; verify with the validation plan
between each.**

### Step 1 — Add a second nameserver

Standard practice (and most registrars require it). Two
realistic options:

* **Second Fly app in a different region** —
  `exdns-test-iad` mirroring `exdns-test-lhr`, fed via
  primary→secondary AXFR + NOTIFY (see
  [guide 08](../guides/08-secondary-zones-axfr-ixfr-notify.md)).
  Cost: another ~$5 / month.

* **Promote to a 3-node EKV cluster** in Fly — three apps
  with shared cluster identity, EKV peer port open between
  them only. Operationally heavier but is the path to
  multi-region active-active.

For a test domain, option 1 is enough. Move to option 2
only when graduating to a real workload.

### Step 2 — Sign with DNSSEC

Walk through [guide 07](../guides/07-dnssec-signing-and-rollover.md):
generate KSK + ZSK, register the DS at Cloudflare. T1.1
ensures we won't ship expired signatures; the
signing-lag telemetry from T2.5 should be wired into the
Grafana dashboard as a precondition.

### Step 3 — Add DoT (port 853)

* Allocate a TLS cert via Let's Encrypt + DNS-01 (since
  we're now authoritative for the zone, this is easy).
  See [tls-certificate-renewal.md](../guides/runbooks/tls-certificate-renewal.md)
  for the post-hook script.
* Add a `[[services]]` block in `fly.toml` for port 853.
* Re-run validation stage 2 (CryptCheck) until green.

### Step 4 — Add DoH (port 443)

Same recipe as DoT. Conflict to watch: if you also serve
HTTP on the Fly app for any reason, port 443 is taken.

### Step 5 — Adversarial review

At this point the surface is meaningful enough to warrant
external eyes. Trigger validation stage 7. For a test
deployment the bug-bounty path is overkill; a paid
security engineer for a quarter is the right shape.

### Step 6 — Production cut-over

If the test domain has been clean for 60 days, repeat the
whole plan with a real domain and follow the production
half of [guide 04](../guides/04-delegating-your-domain.md).

The path is intentionally slow. DNS errors are loud,
recovery from a botched cut-over takes hours of cache
TTL, and "undo" doesn't exist below the parent zone.
Earn each step.

## Order of operations summary

```
0.  Prerequisites met
1.  fly apps create + volume create                (§1)
2.  fly ips allocate-v4 + v6                       (§2)
3.  Set fly secrets (RELEASE_COOKIE, NSID, NS)     (§3)
4.  Write contrib/fly/runtime.exs + zones.d/*.zone (§3, §4)
5.  Write fly.toml                                 (§4)
6.  Update Dockerfile to copy runtime.exs + zones  (§4)
7.  Cloudflare: register glue (NOT change NS yet)  (§5a)
8.  fly deploy                                     (§6)
9.  Smoke test from outside the Fly network        (§6)
10. Cloudflare: change NS to ns1.<your-domain>     (§5c)
11. Wait for parent-TTL propagation (~1h)          (§7)
12. Run validation stages 1, 4, 5, 6               (§7)
13. Capture results in ops log                     (§7)
14. Soak for two weeks                             (§9)
15. Begin graduation steps 1–6                     (§9)
```

If anything in 1–13 trips, stop, fix, restart from the
last green step. If anything in 14 surfaces, file an
issue and decide before continuing 15.

