# 08 — Secondary zones: AXFR, IXFR, NOTIFY

A **secondary** server holds a copy of a zone whose master copy lives on a **primary**. The primary publishes changes; the secondary pulls them via zone transfer. Combined with DNS NOTIFY (RFC 1996), changes propagate within seconds.

This is the classical, vendor-interoperable way to run a multi-server authoritative deployment. ExDns can play either role — primary, secondary, or both — and interoperates with BIND, Knot, NSD, PowerDNS, and Cloudflare's edge.

> **When to use this vs the EKV cluster.** EKV ([guide 02](02-clustering-with-ekv.md)) is the right answer when *every node is ExDns* and you want one operational surface. Secondary zones are the right answer when you need to interoperate with non-ExDns servers, when the primary is hidden behind a firewall and pushes to public secondaries, or when you can't form a single trust domain across the nodes (cross-organisation hosting, geo-political separation).

## Glossary

* **AXFR** (RFC 5936) — Full zone transfer. The secondary asks for everything; the primary streams every record.
* **IXFR** (RFC 1995) — Incremental transfer. The secondary names the SOA serial it has; the primary streams only the diff.
* **NOTIFY** (RFC 1996) — Lightweight UDP message from primary to secondary saying "the zone changed; come refresh."
* **Hidden primary** — A primary that's not advertised in the zone's NS records. Holds the master copy, NOTIFYs the public secondaries, but doesn't itself answer public queries.
* **TSIG** (RFC 8945) — Shared-secret HMAC that authenticates zone transfers. Always use it.

## Set up TSIG keys

Don't run zone transfers in the open — anyone who can reach port 53 can pull your full zone, harvesting records you'd rather keep private. TSIG fixes that with a per-direction shared secret.

Generate a key — same algorithm and secret on **both** primary and secondary:

```bash
# 256 bits of HMAC-SHA256 entropy.
SECRET=$(openssl rand -base64 32)
echo "$SECRET"
# RYn2yLM... etc.
```

Configure on the primary:

```elixir
# primary's config/runtime.exs
config :ex_dns, :tsig_keys, %{
  "transfer.example.com." => %{
    algorithm: "hmac-sha256.",
    secret_base64: System.get_env("TRANSFER_KEY")
  }
}

config :ex_dns, :transfer_acls, %{
  "example.com" => [
    {:tsig, "transfer.example.com."}
  ]
}
```

Configure on the secondary the matching keyring entry (so it can sign its AXFR/IXFR requests):

```elixir
# secondary's config/runtime.exs
config :ex_dns, :tsig_keys, %{
  "transfer.example.com." => %{
    algorithm: "hmac-sha256.",
    secret_base64: System.get_env("TRANSFER_KEY")
  }
}
```

Inject `TRANSFER_KEY` from your secrets store. Same value on both hosts.

## Configure the secondary

```elixir
# secondary's config/runtime.exs
config :ex_dns, :secondary_zones, [
  %{
    apex: "example.com",
    primaries: [{{203, 0, 113, 10}, 53}],
    tsig_key: "transfer.example.com.",
    initial_refresh_seconds: 30,
    initial_retry_seconds: 10,
    initial_expire_seconds: 86_400
  }
]
```

Restart the secondary. It will:

1. Connect to the primary, send `AXFR/IN example.com.` signed with the TSIG key.
2. Stream the full zone over TCP.
3. Cache the SOA serial and start serving.
4. From then on, on the SOA refresh interval, send `IXFR` with the cached serial. The primary streams only the diff.

Watch the state with:

```bash
TOKEN='<viewer or zone_admin token>'
curl -sS -H "authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:9571/api/v1/secondaries/example.com | jq
```

Or via the UI: **Secondaries** tab.

States the secondary moves through:

| State | Meaning |
|---|---|
| `pending` | Waiting for first refresh. |
| `refreshing` | AXFR or IXFR in progress. |
| `loaded` | Have a copy, serving normally. |
| `expired` | Past SOA expire — refusing to serve (RFC 1035). |
| `error` | Last refresh failed; will retry per SOA retry. |

## Configure NOTIFY on the primary

Without NOTIFY, the secondary discovers changes only at SOA refresh (default 7200s = 2h). With NOTIFY, propagation is sub-second.

```elixir
# primary's config/runtime.exs
config :ex_dns, :notify_targets, %{
  "example.com" => [
    {{198, 51, 100, 50}, 53},     # secondary 1
    {{198, 51, 100, 51}, 53}      # secondary 2
  ]
}
```

Now every successful zone change (file reload, API mutation, dynamic UPDATE) fires a NOTIFY at every listed secondary, which immediately initiates an IXFR.

## Configure NOTIFY ACLs on the secondary

By default a secondary accepts NOTIFY only from its configured primaries. To explicitly allow additional senders (e.g. for a hidden-primary setup where the visible NS records advertise a different IP):

```elixir
# secondary's config/runtime.exs
config :ex_dns, :notify_acls, %{
  "example.com" => [
    {:cidr, {{203, 0, 113, 0}, 24}},
    {:tsig, "transfer.example.com."}
  ]
}
```

Combinations of `:cidr` and `:tsig` AND together — the request must match every entry. Multiple ACL entries OR together.

## Verify end-to-end

On the primary:

```bash
# Make a change.
TOKEN='<zone_admin>'
curl -sS -X POST -H "authorization: Bearer ${TOKEN}" \
  -H "content-type: application/json" \
  http://127.0.0.1:9571/api/v1/zones/example.com/records \
  -d '{"name":"new","type":"A","ttl":300,"data":"203.0.113.99"}'
```

On the secondary, within ~250 ms:

```bash
dig @127.0.0.1 -p 53 new.example.com A +short
# 203.0.113.99
```

The secondary's logs should show:

```
ExDns.Notify: received NOTIFY for example.com from 203.0.113.10
ExDns.Zone.Secondary[example.com]: refreshing (IXFR; cached serial 2026010101)
ExDns.Zone.Secondary[example.com]: IXFR ok (new serial 2026010102, +1 records)
```

## Force a refresh

Don't want to wait for SOA refresh and don't have NOTIFY wired up? Force one from the API:

```bash
curl -sS -X POST -H "authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:9571/api/v1/secondaries/example.com/refresh
```

…or click **Refresh** on the UI's **Secondaries** row.

## Common topology — hidden primary, two public secondaries

Most respectable production deployments look like this:

```
                   ┌──────────────────┐
                   │  hidden primary  │
                   │  (no public NS)  │
                   └────────┬─────────┘
                            │
                NOTIFY      │      AXFR / IXFR
                  + TSIG    │      + TSIG
                            │
              ┌─────────────┴─────────────┐
              │                           │
     ┌────────▼────────┐         ┌────────▼────────┐
     │   ns1.example   │         │   ns2.example   │
     │   (secondary)   │         │   (secondary)   │
     │   advertised    │         │   advertised    │
     └─────────────────┘         └─────────────────┘
```

Why:

* The primary holds the canonical zone source, never answers public queries, lives on the most-locked-down network you have.
* Public secondaries take the operational risk of internet exposure.
* Compromising a public secondary loses you that one host's serving capacity, not your master copy.

## RFC 2136 Dynamic UPDATE

Independent of zone transfers — `nsupdate` from a TSIG-authenticated client can mutate the primary's zone live:

```elixir
# primary's config/runtime.exs
config :ex_dns, :update_acls, %{
  "example.com" => [
    {:cidr, {{10, 0, 0, 0}, 8}},
    {:tsig, "ddns.example.com."}
  ]
}

# Per-zone policy: "we require TSIG on every UPDATE". 'optional'
# (the default) accepts unsigned UPDATEs from CIDR-allowed clients
# but signs the response if the request was signed.
config :ex_dns, :require_tsig, %{
  "example.com" => :required
}
```

Then from a client:

```bash
nsupdate -k /etc/exdns/tsig/ddns.example.key <<EOF
server primary.example.com
zone example.com.
update add api.example.com. 300 A 203.0.113.42
send
EOF
```

The change applies atomically (RFC 2136 prerequisite checks honoured), the SOA bumps once, and NOTIFYs fire at every configured secondary.

## Operational notes

* **Tighten ACLs.** A misconfigured `transfer_acls` is the classic "I leaked my whole zone" mistake. Default-deny.
* **Match clocks.** TSIG uses timestamps with a 5-minute fudge (RFC 8945). NTP is mandatory.
* **Watch the journal.** ExDns persists IXFR diffs in a journal under the EKV `zone/<apex>/journal/` prefix. Useful for forensics and for serving IXFR to secondaries that ask for older serials.
* **Set sane SOA timers.** `refresh: 7200, retry: 3600, expire: 1209600, minimum: 3600` is fine for most. Don't go below `refresh: 600` — it just hammers the primary without buying you anything.
* **Test failure.** Stop the primary, watch the secondaries hold steady on their cached copy until `expire`. Restart the primary; secondaries refresh at next NOTIFY or refresh interval.

## Related guides

* [01 — Installation, configuration & basic operations](01-installation-and-basic-operations.md)
* [02 — Extending to a clustered environment](02-clustering-with-ekv.md) — when EKV is a better fit than zone transfers.
* [04 — Delegating your domain](04-delegating-your-domain.md) — for the public-NS context.
* [07 — DNSSEC signing & rollover](07-dnssec-signing-and-rollover.md) — DNSSEC and zone transfers compose naturally.
