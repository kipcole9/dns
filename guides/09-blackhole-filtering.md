# 09 — BlackHole filtering (pi-hole-equivalent)

The `BlackHole` plugin turns ExDns into a network-wide ad / tracker / malware filter, the way pi-hole or AdGuard Home do. Subscribe to remote adlists, curate per-group allow / deny rules, scope filtering to specific client CIDRs, log every query for inspection.

This is the canonical example of a filtering plugin in the ExDns plugin pipeline ([guide 03](03-server-modes-authoritative-recursive-stub.md) covers the resolver-mode side of plugins). Reading [guide 06](06-zone-management-via-the-web-ui.md) first for the UI walkthrough is helpful but not required.

## Concepts

* **Blocklist** — A remote URL (hosts file / dnsmasq / AdGuard / plain-domain format) that BlackHole subscribes to and refreshes on a schedule. Compiled into a fast match set.
* **Allowlist** — Domains that match a blocklist but should be answered normally. "Yes I know `googletagmanager.com` is on Steven Black's list, but I need it for my dayjob."
* **Denylist** — Domains to block even if no subscribed blocklist mentions them. Local additions.
* **Group** — A CIDR + a set of subscribed blocklists. Filtering only applies to clients whose source IP falls inside one of a group's CIDRs. No group covers a client → BlackHole passes the query through unchanged.
* **Decision** — `:allow` (record query, pass through), `:block` (return the configured block response — NXDOMAIN by default), `:passthru` (no group covers this client).

## Enable the plugin

Two changes to `config/runtime.exs` — wire the plugin pipeline as the resolver, configure BlackHole:

```elixir
# Plugin pipeline replaces the bare resolver.
config :ex_dns,
  resolver_module: ExDns.Resolver.Plugins

config :ex_dns, :plugin_pipeline,
  underlying: ExDns.Resolver.Hybrid    # or Default / Forwarder, pick per guide 03

# BlackHole settings.
config :ex_dns, :black_hole,
  enabled: true,
  default_block_response: :nxdomain,    # or :nodata, :sinkhole_a
  query_log_capacity: 100_000,
  query_log_max_age_seconds: 604_800,   # 7 days
  default_subscriber_interval_seconds: 86_400
```

Storage defaults to EKV (cluster-replicated). For very high query rates you might prefer SQLite — see the storage note in [the changelog](../CHANGELOG.md):

```elixir
config :ex_dns, :black_hole,
  enabled: true,
  storage:
    {ExDns.BlackHole.Storage.SQLite,
     [path: "/var/lib/exdns/black_hole.sqlite"]}
```

Restart the server. The plugin self-registers on boot.

## Add a group — until you do this, nothing is filtered

A group is the gate. Without a group whose CIDRs cover a client, BlackHole has no opinion and the query flows through untouched. This is intentional — it means installing the plugin doesn't suddenly start filtering everyone.

Via the API:

```bash
TOKEN='<zone_admin>'

api() {
  curl -sS \
    -H "authorization: Bearer ${TOKEN}" \
    -H "content-type: application/json" "$@"
}

# Group covering the LAN.
api -X POST http://127.0.0.1:9571/api/v1/plugins/black_hole/actions/put_group \
  -d '{
    "name": "lan",
    "enabled": true,
    "cidrs": ["192.168.0.0/16"],
    "blocklist_ids": []
  }' | jq
# {"data": {"id": "...", "name": "lan", ...}}
```

Or in the UI: **Plugins** → **Black Hole** → **Groups** → **Add group**.

## Subscribe to a blocklist

The classic starter set:

```bash
api -X POST http://127.0.0.1:9571/api/v1/plugins/black_hole/actions/put_blocklist \
  -d '{
    "id": "stevenblack",
    "name": "Steven Black unified hosts",
    "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "enabled": true
  }'

api -X POST http://127.0.0.1:9571/api/v1/plugins/black_hole/actions/put_blocklist \
  -d '{
    "id": "adguard-base",
    "name": "AdGuard base",
    "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "enabled": true
  }'

# Trigger an immediate fetch (without waiting for the scheduled refresh).
api -X POST http://127.0.0.1:9571/api/v1/plugins/black_hole/actions/refresh_blocklist \
  -d '{ "id": "stevenblack" }'
```

The subscriber fetches the URL on a jittered interval (defaults to 24h), parses the format, deduplicates against other subscribed lists, and updates the compiled match set in-process.

Now bind the blocklists to the group:

```bash
GROUP_ID=$(api http://127.0.0.1:9571/api/v1/plugins/black_hole/resources/groups \
  | jq -r '.data[] | select(.name=="lan").id')

api -X POST http://127.0.0.1:9571/api/v1/plugins/black_hole/actions/put_group \
  -d "{
    \"id\": \"${GROUP_ID}\",
    \"name\": \"lan\",
    \"enabled\": true,
    \"cidrs\": [\"192.168.0.0/16\"],
    \"blocklist_ids\": [\"stevenblack\", \"adguard-base\"]
  }"
```

## Verify it's filtering

From a LAN client (or fake the source IP with `dig -b`):

```bash
# A known-blocked tracker domain.
dig @192.168.1.1 doubleclick.net A
# status: NXDOMAIN

# A known-allowed domain.
dig @192.168.1.1 example.com A
# status: NOERROR
```

From outside the LAN CIDR:

```bash
dig @192.168.1.1 doubleclick.net A
# status: NOERROR — no group covers this client, query passes through.
```

## Local additions — denylist + allowlist

Block a domain that no list mentions:

```bash
api -X POST http://127.0.0.1:9571/api/v1/plugins/black_hole/actions/put_deny \
  -d '{
    "domain": "tracker.acme.example",
    "comment": "internal: identified during incident response 2026-04-12"
  }'
```

Allow a domain that lists block:

```bash
api -X POST http://127.0.0.1:9571/api/v1/plugins/black_hole/actions/put_allow \
  -d '{
    "domain": "googletagmanager.com",
    "comment": "needed for marketing dashboard"
  }'
```

Allowlist always wins over denylist and over blocklists. Denylist always wins over blocklist.

## The query log

Every decision (allow, block, or passthru) is logged with timestamp, client IP, qname, qtype, decision, matched-list-id, response code, latency. Tail it via the SSE event stream:

```bash
curl -N -H "authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:9571/api/v1/events
# event: query.logged
# data: {"client_ip":"192.168.1.50","qname":"doubleclick.net","decision":"block","matched_list_id":"stevenblack",...}
```

Or paginate the historical log:

```bash
api 'http://127.0.0.1:9571/api/v1/plugins/black_hole/resources/query_log?limit=200' | jq
```

The Web UI's Black Hole dashboard renders these as a live feed plus top-N tables and totals tiles.

Retention is bounded by `:query_log_max_age_seconds` (7 days default). The sweeper runs hourly and deletes anything older.

## Block response choices

```elixir
config :ex_dns, :black_hole,
  default_block_response: :nxdomain
```

| Choice | What the client sees |
|---|---|
| `:nxdomain` | The strongest negative answer. Clients give up immediately. **Default** — recommended. |
| `:nodata` | The name exists, the type doesn't. Clients try the next type (e.g. AAAA after A). Slightly slower failures. |
| `:sinkhole_a` | A configured A record (e.g. `0.0.0.0`). Lets you redirect to a "blocked by your DNS" page. |

The choice affects user experience more than security: every option blocks the lookup; the difference is how loudly the client retries.

## Performance

* Match set is compiled into a single binary trie checked in O(label-count). Cost per query: tens of microseconds.
* Subscribers fetch and parse off the hot path.
* Query log writes are append-only and asynchronous to the answer return.
* Default capacity (100k entries × 7d) holds easily on a single SQLite file or in EKV.

## Operating it

* **Don't subscribe to lists you haven't read.** Some hosts files block legitimate CDN edges and break the internet for confused users.
* **Allowlist generously when you start.** Watch the live feed for a few days, allowlist anything that matters to you.
* **Group your clients.** Kid's phone in one group with strict lists; work laptop in another with relaxed lists; guest network in a third with malware-only lists.
* **Roll your blocklist URLs.** If Steven Black rebrands, the URL changes. Update the row.
* **Backup the storage.** EKV data dir or SQLite file. Same backup story as any other state.

## Writing your own filtering plugin

BlackHole is just a `ExDns.Plugin.Policy` implementation. Any module that:

* implements `routes/0` (a list of `{cidr, qname_suffix, qtype, priority}` tuples), and
* implements `policy_resolve/2` (returns `{:answer, message}` or `:passthru`)

…can be registered and slot into the same dispatch path.

See `lib/ex_dns/black_hole/plugin.ex` for a complete reference implementation.

## Related guides

* [03 — Server modes](03-server-modes-authoritative-recursive-stub.md) — the plugin pipeline lives at the resolver level.
* [05 — Zone management via curl](05-zone-management-via-curl.md) — the plugin actions/resources endpoints.
* [06 — Zone management via the Web UI](06-zone-management-via-the-web-ui.md) — the BlackHole dashboard.
* [10 — Monitoring & observability](10-monitoring-and-observability.md) — alerting on filtering rates.
