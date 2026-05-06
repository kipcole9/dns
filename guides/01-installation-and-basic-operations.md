# 01 — Installation, configuration & basic operations

This guide walks you through bringing up a single-node ExDns server and the `dns_ui` web interface on one machine, configuring both for development, then exercising the basics: loading a zone, querying it, reloading on disk change, and graceful shutdown.

If you want a clustered deployment, work through this guide first, then read [02 — Extending to a clustered environment](02-clustering-with-ekv.md).

## Prerequisites

* **Elixir 1.17+** with **OTP 27+**. EKV (the embedded KV store powering durability and clustering) ships precompiled NIFs for common platforms; on others you'll need a working C toolchain.
* **`dig`** (any recent version). The integration tests use it, and every example below is a `dig` you can run.
* About **300 MB** of disk for the build artefacts and another **50 MB** of state per loaded zone.

## Get the source

```bash
git clone https://github.com/kipcole9/dns.git ~/Development/dns
git clone https://github.com/kipcole9/dns_ui.git ~/Development/dns_ui

cd ~/Development/dns
mix deps.get
mix compile
mix test       # ~25 seconds, ~1200 tests; should pass clean
```

The two repos are sibling Mix projects with **zero compile-time coupling**. The UI talks to the server only via the formal HTTP API documented at `dns/priv/openapi/v1.yaml`.

## Where state lives

Out of the box, every persistent subsystem stores its state in a shared embedded KV store under `System.tmp_dir!()/ex_dns_ekv`. Fine for a five-minute kick of the tyres, wrong for anything you care about. Override the data directory before you start the server in earnest:

```elixir
# config/runtime.exs
import Config

config :ex_dns, :ekv,
  enabled: true,
  data_dir: "/var/lib/exdns/ekv",
  cluster_size: 1,
  mode: :member
```

`cluster_size: 1` is single-node mode. The same code path serves a multi-node cluster when you raise it — see guide 02.

## Minimum useful configuration

Pick a port (53 in production, anything ≥ 1024 in dev), enable the API, point it at a zone file, and turn on the snapshot so runtime mutations survive restart:

```elixir
# config/runtime.exs
import Config

config :ex_dns,
  listener_port: System.get_env("EXDNS_PORT", "5353") |> String.to_integer(),
  zones: ["/etc/exdns/zones.d/*.zone"]

config :ex_dns, :nsid,
  enabled: true,
  identifier: "ns1.example"

config :ex_dns, :api,
  enabled: true,
  port: 9571,
  bind: {127, 0, 0, 1},
  token_path: "/var/lib/exdns/tokens.json"

config :ex_dns, :zone_snapshot,
  enabled: true,
  path: "/var/lib/exdns/snapshot.bin"
```

Binding to port 53 needs the BEAM to be permitted to bind low ports. On Linux: `setcap 'cap_net_bind_service=+ep' "$(readlink -f $(which beam.smp))"`. On macOS development: stick to 5353.

## Write your first zone file

Zones are plain RFC 1035 master files. Save this as `/etc/exdns/zones.d/example.test.zone`:

```dns
$TTL 3600
$ORIGIN example.test.
@           IN  SOA   ns1.example.test. hostmaster.example.test. (
                 2026010101 ; serial — bump on every change
                 7200       ; refresh
                 3600       ; retry
                 1209600    ; expire
                 3600 )     ; minimum / negative TTL
            IN  NS    ns1.example.test.
ns1         IN  A     127.0.0.1
www         IN  A     127.0.0.1
api         IN  A     127.0.0.1
```

ExDns validates every zone on load: the SOA serial must move forward (RFC 1982 wraparound rules), CNAMEs may not coexist with other types at the same name, glue must be in-bailiwick. Bad reloads return a structured error and leave the previously-loaded zone in place.

## Issue an API token

The HTTP API is bearer-token protected on every endpoint. There are three roles in a strict hierarchy:

| Role | What it can do |
|---|---|
| `viewer` | Read-only — list zones, read records, watch the SSE event stream. |
| `zone_admin` | Everything `viewer` can, plus mutate records, reload zones, refresh secondaries, dispatch plugin actions. Restricted by zone-glob scope. |
| `cluster_admin` | Everything `zone_admin` can on every zone, plus DNSSEC rollover, plugin registration, and any future cluster-wide operation. |

Issue your first token:

```bash
cd ~/Development/dns
mix exdns.token.issue --role zone_admin --scopes "*"
```

The secret prints once. Copy it out of the terminal immediately — there is no way to retrieve it later, and a forgotten secret is just garbage in the token store. The `id` is safe to log; the `secret` is not.

Two more useful invocations:

```bash
# A read-only token for a dashboard.
mix exdns.token.issue --role viewer --label "grafana"

# A scoped token for a tenant who only owns one zone.
mix exdns.token.issue \
  --role zone_admin \
  --scopes "tenant-7.example,*.tenant-7.example" \
  --label "tenant-7"
```

## Start the server

```bash
mix run --no-halt
```

You should see the EKV instance come up, then UDP + TCP listeners, then the API on port 9571. Hit `Ctrl-C` twice to exit; we'll cover graceful drain below.

## First queries

```bash
# Authoritative answer from the zone you just loaded.
dig @127.0.0.1 -p 5353 www.example.test A +short
# 127.0.0.1

# NXDOMAIN with AA=1 inside a known zone.
dig @127.0.0.1 -p 5353 nope.example.test A
# status: NXDOMAIN, flags: qr aa rd

# NSID echoes back your server identifier.
dig @127.0.0.1 -p 5353 example.test SOA +nsid
# NSID: 6e 73 31 2e 65 78 61 6d 70 6c 65 ("ns1.example")
```

If `dig` reports `connection refused`, the listener isn't bound — check `EXDNS_PORT` and any other DNS service hogging the same port.

## Reload a zone after editing

Bump the SOA serial in the zone file (the validator rejects reloads that don't), then reload via the API:

```bash
TOKEN='<paste the secret you copied>'

curl -sS -X POST http://127.0.0.1:9571/api/v1/zones/example.test/reload \
  -H "authorization: Bearer ${TOKEN}"
```

Or via the bundled CLI:

```bash
bin/exdnsctl zone reload example.test
```

A failed reload (bad SOA, dangling glue, CNAME conflict) returns `{ "error": ..., "problems": [...] }` and the previous zone keeps serving — there's no half-loaded state.

## Bring up the Web UI

In a second terminal:

```bash
cd ~/Development/dns_ui
mix deps.get
mix compile

# Map a UI user to the bearer token you issued above.
mix dns_ui.user.create \
  --email you@example.com \
  --password 's3cret' \
  --bearer-token '<the secret>' \
  --label admin

EXDNS_API_URL=http://127.0.0.1:9571 mix phx.server
```

Open <http://localhost:4000> → sign in. You should see your `example.test` zone, drill into the record table, edit a record inline, and watch the SSE event stream broadcast the change back. UI workflows are covered in detail in [06 — Zone management via the Web UI](06-zone-management-via-the-web-ui.md).

## Graceful drain

ExDns supports a clean shutdown: readiness flips, listeners close, in-flight workers complete, the IXFR journal flushes, then the BEAM exits. Trigger it with:

```bash
bin/exdnsctl drain
```

…or just `Ctrl-C Ctrl-C` in the foreground process. The same drain runs on `SIGTERM` from systemd, so a `systemctl stop exdns` is safe.

## What's next

* **Cluster it**: [02 — Extending to a clustered environment](02-clustering-with-ekv.md)
* **Pick the right server mode**: [03 — Server modes](03-server-modes-authoritative-recursive-stub.md)
* **Make it the public NS for a real domain**: [04 — Delegating your domain](04-delegating-your-domain.md)
* **Drive zone CRUD from scripts**: [05 — Zone management via curl](05-zone-management-via-curl.md)

