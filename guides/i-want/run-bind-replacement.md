# I want to replace BIND

You're running BIND today. You read RFCs, you maintain
`named.conf`, you know what `rndc reconfig` does. You
want a working ExDns deployment that your existing
operational habits transfer to.

## What you can expect to keep

| BIND habit | ExDns equivalent |
|---|---|
| `named.conf` checked into git | `runtime.exs` checked into git |
| `named-checkconf` | `exdns doctor [--strict]` |
| `rndc reload` | `exdns zone reload <apex>` (currently reloads all) |
| `rndc dumpdb` | `curl /api/v1/zones/<apex>/records` |
| `rndc status` | `exdns status` |
| `dnssec-keygen` + `dnssec-signzone` | `bin/exdnsctl key generate` (auto-signing daemon) |
| Master / slave with TSIG | Primary / secondary with TSIG (guide 08) |
| Views (`view "internal"`) | `:view_acls` per-zone (guide 06) |
| Logging channels | Telemetry → Prometheus / structured-logger / dnstap |

## What's different

* **Config-as-code in Elixir.** `runtime.exs` is
  Elixir-shaped, not BIND-shaped. The semantic
  ground is the same; the syntax isn't.
* **EKV state.** State that BIND keeps in memory is
  persisted in the EKV substrate at `/var/lib/exdns/ekv`.
  Survives restart, replicates across nodes when you
  scale.
* **HTTP API as a first-class operator surface.**
  Every operation has a `curl`-able endpoint. `rndc`'s
  control channel is replaced by `/api/v1/*`.
* **Web UI as a daily-ops tool, not the source of
  truth.** Operators who want pure config-as-code stay
  in `runtime.exs`; the UI is for inspection and
  one-off mutations.

## Steps

### 1. Install in `MIX_ENV=prod` mode

Either:

```bash
# A: precompiled tarball
curl -fsSL https://raw.githubusercontent.com/kipcole9/dns/main/contrib/install/install.sh | sudo bash
```

…or:

```bash
# B: from source (you want this if you're doing
# upstream bug-fixing or running a non-tagged version)
git clone https://github.com/kipcole9/dns
cd dns
mix deps.get
MIX_ENV=prod mix release ex_dns
# Tarball at _build/prod/ex_dns-<version>.tar.gz
```

### 2. Port your zones

ExDns reads RFC 1035 master files. Most BIND zone files
work as-is.

```bash
sudo cp /var/named/master/yourdomain.com /etc/exdns/zones.d/
sudo systemctl reload exdns
exdns doctor   # surface anything the parser doesn't like
```

If you have records the static-loader grammar doesn't
support yet, see
[plans/zone_parser_followups.md](../../plans/zone_parser_followups.md)
for the current gaps + workarounds (most rare types are
addable via the API).

### 3. Wire your existing observability

* **Prometheus**: scrape `:9573/metrics`. The shipped
  Grafana dashboard JSON is at
  `contrib/grafana/exdns.json`.
* **Logging**: structured logfmt to stdout by default.
  `journalctl -u exdns` works. Pipe through Vector or
  Fluentbit if you have a centralised log infra.
* **dnstap**: enabled via `:ex_dns, :dnstap, [enabled:
  true, sink: {:file, "..."}]`. Same fstrm format BIND
  emits, so existing tooling Just Works.

### 4. Migrate DNSSEC keys

If your zones are signed today:

* **Easy path**: roll new keys with ExDns, do a normal
  KSK rollover at the registrar. Your old BIND keys
  retire naturally.
* **Hard path**: import existing private keys into the
  ExDns key store directly. Not yet a one-line CLI;
  see `lib/ex_dns/dnssec/key_store.ex` for the
  programmatic path.

### 5. Set up a secondary

Configure your old BIND server (or a second ExDns
instance) as a secondary, AXFR/IXFR-fed via TSIG. Walk
through [guide 08](../08-secondary-zones-axfr-ixfr-notify.md).

### 6. Cut over at the registrar

Once both nameservers are answering correctly:

1. Update glue at the registrar.
2. Update NS records.
3. Wait for parent-zone propagation.
4. Verify with [DNSViz](https://dnsviz.net/) +
   [Zonemaster](https://zonemaster.net/).
5. Decommission BIND.

## Day-to-day

* `exdns status` for a quick health check.
* `exdns doctor --strict` in CI before deploys.
* `exdns zone reload <apex>` after editing a file.
* Web UI for ad-hoc inspection or "what changed when".
* `journalctl -u exdns -f` for live logs.

## Documentation map

* **Architecture & internals**: [`README.md`](../../README.md).
* **Every operator workflow**: [`guides/`](../).
* **Bad-day SOPs**: [`guides/runbooks/`](../runbooks/).
* **Plans + audit history**: [`plans/`](../../plans/).
* **OpenAPI spec**: [`priv/openapi/v1.yaml`](../../priv/openapi/v1.yaml).
* **CHANGELOG**: [`CHANGELOG.md`](../../CHANGELOG.md).

## Where to go next

If you've migrated zones cleanly, run the full
[external validation plan](../../plans/external_validation_plan.md)
against your new setup before flipping NS records. The
six-stage gate is intentionally cautious; running it
catches the things internal CI can't.
