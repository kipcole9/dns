# BlackHole plugin — plan

**Date:** 2026-05-06
**Status:** Plan only — no implementation work yet.
**Touches:** new `ExDns.BlackHole.*` modules under `lib/ex_dns/black_hole/`, small extensions to `ExDns.Plugin` and the resolver pipeline, new pages in `dns_ui` driven through the existing plugin tab contract.

## Goal

Ship a pi-hole-equivalent capability — DNS-based blocklist filtering with subscription-managed adlists, allowlists, per-client policy, query log, and a dashboard — implemented as a *server-side policy plugin* (the **BlackHole** plugin) and surfaced as a tab in the sibling `dns_ui` app. Operators who today run pi-hole next to their resolver should be able to swap to ExDns + the BlackHole plugin and lose no functionality. The name is borrowed from the BGP / IP-routing convention: a "black-hole route" silently drops traffic; this plugin synthesises the DNS-layer equivalent.

## What pi-hole is, in one paragraph

Pi-hole is the inspiration. It intercepts every DNS query a client makes, looks the qname up against a compiled set of "blocked" domains (typically aggregated from third-party adlists), and either returns NXDOMAIN / 0.0.0.0 / `::` (a "block") or forwards the query to the upstream resolver as normal. It has a web admin UI for managing the lists, browsing the per-query log, viewing dashboards (top queries, top blocked, top clients), and grouping clients by CIDR so phones and TVs can have different filter profiles than laptops. The BlackHole plugin matches that capability set without claiming to be pi-hole or compatible with its config files.

## What we already have

| Already in ExDns | Use for BlackHole |
|---|---|
| `ExDns.RPZ.*` (Match / Store / Resolver / Loader) | The block primitive — a domain-keyed lookup that yields a synthesized response. BlackHole's matcher sits next to RPZ; both populate compatible rule sets. |
| `ExDns.Plugin` + `ExDns.Plugin.Registry` | Plugin lifecycle + UI metadata + per-resource passthrough. BlackHole becomes one entry in this registry. |
| `ExDns.API.Router` `/api/v1/plugins/:slug/resources/:resource` | Read-only data surface that the UI consumes (overview, blocklists, query log, etc.). |
| `dns_ui` `PluginTabLive` | Generic table / kv views are enough for read-only screens; mutations need a small extension. |
| `:telemetry` events on every query | Already firing — BlackHole hooks them for the query log + counters. |
| `ExDns.API.Events` SSE stream | Live "query just landed" updates piped into the dashboard. |

## What's missing (and that this plan adds)

1. **CIDR-routed plugin dispatch.** Today `ExDns.Plugin` has `metadata/0` + optional `get_resource/1`. BlackHole (and anycast, and any future policy plugin) needs the registry to maintain a routing table keyed on `{source_ip_cidr, qtype, qname_suffix}`, and the resolver pipeline needs to consult that table on every query — dispatching to *at most one* matching plugin via a new `policy_resolve/2` callback. Queries that match no route flow through the normal resolver as if no plugins were installed. This routing layer is the single primitive that serves both BlackHole-style filtering (recursive/stub resolver) and anycast-style synthesis (authoritative zones); both register CIDRs, just with different `qname_suffix` scopes.

2. **Plugin mutations from the UI.** Today plugin routes are read-only. Adding a domain to the allowlist, refreshing adlists, etc. need a `POST /api/v1/plugins/:slug/actions/:name` route that dispatches to a `handle_action/2` callback.

3. **The BlackHole subsystem** — adlist fetcher, compiled match set, allowlist, denylist, group/CIDR table, query log, stats counters, and a pluggable storage backend (SQLite by default).

4. **UI screens** that are richer than a single auto-rendered table. Phase-2 ships them through the generic plugin tab primitives we already have; Phase-3 lights up plugin-owned custom LiveViews per the original §5 plan.

## Architecture

```
                       ┌─────────────────────────────────┐
                       │   ExDns.BlackHole.Plugin        │
                       │   @behaviour ExDns.Plugin       │
                       │   @behaviour ExDns.Plugin.Policy│
                       └──┬─────────────────────────┬────┘
                          │                         │
   routes/0 +             │                         │ get_resource/1
   policy_resolve/2       │                         │ handle_action/2
   (per-query hook)       │                         │
                          ▼                         ▼
              ┌────────────────────┐    ┌─────────────────────┐
              │ ExDns.BlackHole.Set│    │ ExDns.BlackHole.    │
              │ (compiled matcher) │    │ Lists.Subscriber    │
              └────────┬───────────┘    │ (adlist polling)    │
                       │                └──────────┬──────────┘
                       │                           │
              ┌────────┴───────────────────────────┴────────┐
              │   ExDns.BlackHole.Storage (behaviour)       │
              │   default impl: ExDns.BlackHole.Storage.SQLite│
              │   blocklists, allowlist, denylist,          │
              │   groups (CIDR → list ids), query log       │
              └─────────────────────────────────────────────┘
```

### Module layout

```
lib/ex_dns/black_hole/
├── plugin.ex                  ← Plugin + Plugin.Policy behaviour impl
├── set.ex                     ← compiled match set + matcher
├── storage.ex                 ← Storage behaviour (pluggable backends)
├── storage/
│   └── sqlite.ex              ← default impl (`exqlite` / `ecto_sqlite3`)
├── lists/
│   ├── subscriber.ex          ← GenServer: refresh on schedule
│   ├── fetcher.ex             ← Req-based HTTP client
│   └── parser.ex              ← hosts / dnsmasq / AdGuard formats
├── query_log.ex               ← writer + paginated reader
├── stats.ex                   ← in-memory counters (snapshot to Storage)
└── groups.ex                  ← CIDR → list-id lookup
```

## Plugin framework extensions

### 1. `ExDns.Plugin.Policy` behaviour (new)

A plugin opts into per-query interception by implementing this behaviour and declaring **routes** — the source-IP CIDRs (and optional qtype / qname-suffix filters) it wants to be consulted for. The registry maintains the route table; the resolver does a single longest-prefix lookup per query and dispatches to at most one plugin.

```elixir
defmodule ExDns.Plugin.Policy do
  @type route :: %{
          required(:cidrs) => [{:inet.ip_address(), 0..128}],
          optional(:qtypes) => [atom()] | :any,
          optional(:qname_suffix) => binary() | nil,
          optional(:priority) => integer()
        }

  @callback routes() :: [route()]

  @callback policy_resolve(ExDns.Request.t(), matched_route :: route()) ::
              :cont
              | {:halt, ExDns.Message.t()}
              | {:halt, :nxdomain}
              | {:halt, {:redirect, :inet.ip_address()}}

  @optional_callbacks routes: 0
end
```

* `cidrs` — required. List of `{ip, prefix_len}`. Use `{0, 0, 0, 0}/0` + `{0, 0, 0, 0, 0, 0, 0, 0}/0` for "every client" (rarely correct; needs a low priority).

* `qtypes` — default `:any`. Anycast typically narrows to `[:a, :aaaa]`; BlackHole leaves it `:any`.

* `qname_suffix` — default `nil` (any qname). Authoritative plugins set this to the zone they answer for, e.g. `"example.com"`, so they're only consulted for queries inside that zone.

* `priority` — default `50`. Tiebreaker when multiple plugins match the same query at the same prefix length; higher wins. Same-priority ties resolve to registration order.

`policy_resolve/2` receives the matched route alongside the request — the plugin doesn't repeat source-IP / qtype / suffix checks because the registry has already filtered.

### 2. The route table

`ExDns.Plugin.Registry` builds a route index from every registered plugin's `routes/0`. Each entry is keyed for fast longest-prefix match (a radix trie on the source IP plus a small filter list for qtype + qname suffix). The index lives in `:persistent_term` so per-query reads are lock-free.

Lookup contract — `Registry.match(request)`:

1. Walk the trie on `request.source_ip` to collect every route whose CIDR contains it.

2. Filter by `qtype` (route's `qtypes` is `:any` or includes the qtype).

3. Filter by `qname_suffix` (route is `nil` or the qname ends in the suffix).

4. From what remains, pick: longest CIDR prefix → most specific route wins; higher `priority` → tiebreaker; earliest `register/1` call → final tiebreaker.

5. Return `{:ok, plugin_module, route}` or `:none`.

`:none` means the resolver pipeline runs as if no plugin existed — pass-through is the *floor*, not a plugin.

### 3. Runtime route updates

A plugin that needs to mutate its routes at runtime (BlackHole adding a group, anycast adding a CDN region) calls:

```elixir
ExDns.Plugin.Registry.update_routes(slug, new_routes)
```

The registry rebuilds the index and atomically swaps the `:persistent_term` reference. In-flight queries either see the old index or the new one; never a half-rebuilt state.

### 4. Resolver-pipeline integration

A new module `ExDns.Resolver.Plugins` is the entry point — the configured `:resolver_module` if any plugin policies are registered. On each request:

```elixir
case Registry.match(request) do
  {:ok, plugin_module, route} ->
    case plugin_module.policy_resolve(request, route) do
      :cont -> underlying().resolve(request)
      {:halt, %Message{} = response} -> response
      {:halt, :nxdomain} -> synthesise_nxdomain(request)
      {:halt, {:redirect, ip}} -> synthesise_a(request, ip)
    end

  :none ->
    underlying().resolve(request)
end
```

When no plugins have `routes/0`, the registry's index is empty and the wrapper inlines a direct call to the underlying resolver — zero overhead.

### 5. Mutation route

```
POST /api/v1/plugins/:slug/actions/:name
body: arbitrary JSON
```

Dispatches to `plugin_module.handle_action(name, params)` and returns the function's `{:ok, payload}` / `{:error, reason}` straight through. Like `get_resource/1`, the callback is optional — plugins that need it implement `@behaviour ExDns.Plugin.Action`.

```elixir
defmodule ExDns.Plugin.Action do
  @callback handle_action(name :: binary(), params :: map()) ::
              {:ok, map()} | {:error, term()}
end
```

### 6. Authorisation

Mutations require the caller's bearer token to carry the `zone_admin` role *and* a scope that matches the plugin slug (e.g. token issued with `--scopes "plugin:black_hole"`). This reuses the existing `ExDns.API.Auth.require_scope/2` plumbing — we just add a synthetic zone name of `"plugin:" <> slug`.

## BlackHole subsystem

### Storage

`ExDns.BlackHole.Storage` is a **behaviour**, not a concrete implementation. It declares the operations the plugin needs (CRUD on lists, allowlist, denylist, groups; append + range-scan + truncate on the query log; key/value get/put for stats snapshots) and ships with a default SQLite-backed implementation.

```elixir
defmodule ExDns.BlackHole.Storage do
  @callback init(options :: keyword()) :: {:ok, state} | {:error, term()}
            when state: term()

  @callback list_blocklists(state) :: [map()]
  @callback put_blocklist(state, map()) :: {:ok, map()} | {:error, term()}
  @callback delete_blocklist(state, id :: binary()) :: :ok

  @callback list_allowlist(state) :: [map()]
  @callback put_allow(state, map()) :: :ok
  @callback delete_allow(state, domain :: binary()) :: :ok

  # mirror for denylist + groups …

  @callback append_query_log(state, entry :: map()) :: :ok
  @callback read_query_log(state, query :: map()) :: %{rows: [map()], next_cursor: term() | nil}
  @callback truncate_query_log(state) :: :ok

  @callback put_kv(state, key :: binary(), value :: term()) :: :ok
  @callback get_kv(state, key :: binary()) :: {:ok, term()} | :error
end
```

The active backend is selected via config; default is SQLite:

```elixir
config :ex_dns, :black_hole,
  storage: {ExDns.BlackHole.Storage.SQLite, [path: "/var/lib/exdns/black_hole.sqlite"]}
```

#### Why SQLite (and not DETS, Postgres, TimescaleDB, TigerBeetle)

* **Not DETS.** Per-table 2 GB limit, brittle on unclean shutdown, no range-scan API. The query log alone outgrows it on a busy resolver.

* **SQLite via `exqlite`** is the right default: ACID, WAL-mode concurrent reads, single file (matches the DNS server's "drop a release on a host" operational model), supports the range / paginated scans the query log needs, no external process to operate, mature ecosystem (Ecto-compatible if we want migrations).

* **Postgres** is the right *clustered* answer for deployments that already operate it. It ships as an alternative `ExDns.BlackHole.Storage.Postgres` adapter when someone needs it — not as a v1 dependency.

* **TimescaleDB / TigerBeetle** are the wrong shape. The query log is bounded retention with simple range scans; no need for hypertables, and TigerBeetle's data model is double-entry accounting.

* **Khepri** is the right answer for in-BEAM clustered storage and ships as an adapter alongside Postgres when the rest of ExDns goes clustered (consistent with `plans/2026-05-02-storage-alternatives.md`).

#### What the SQLite default looks like

```sql
-- Configuration
CREATE TABLE blocklists (
  id           TEXT    PRIMARY KEY,
  url          TEXT    NOT NULL,
  name         TEXT,
  enabled      INTEGER NOT NULL DEFAULT 1,
  last_refresh INTEGER,            -- unix seconds
  last_status  TEXT,
  hash         TEXT
);

CREATE TABLE allowlist (
  domain   TEXT PRIMARY KEY,
  added_at INTEGER NOT NULL,
  added_by TEXT,
  comment  TEXT
);

CREATE TABLE denylist (
  domain   TEXT PRIMARY KEY,
  added_at INTEGER NOT NULL,
  added_by TEXT,
  comment  TEXT
);

CREATE TABLE groups (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  enabled       INTEGER NOT NULL DEFAULT 1,
  cidrs         TEXT NOT NULL,    -- JSON-encoded array
  blocklist_ids TEXT NOT NULL     -- JSON-encoded array
);

-- Time-series
CREATE TABLE query_log (
  ts_ns           INTEGER PRIMARY KEY,
  client_ip       TEXT    NOT NULL,
  qname           TEXT    NOT NULL,
  qtype           TEXT    NOT NULL,
  decision        TEXT    NOT NULL,
  matched_list_id TEXT,
  response_code   INTEGER,
  latency_us      INTEGER
);

CREATE INDEX query_log_qname_ts ON query_log(qname, ts_ns DESC);
CREATE INDEX query_log_client_ts ON query_log(client_ip, ts_ns DESC);

-- Snapshots
CREATE TABLE kv (
  key   TEXT PRIMARY KEY,
  value BLOB NOT NULL
);
```

Retention on the query log is a periodic `DELETE FROM query_log WHERE ts_ns < ?` with operator-tunable cap (rows or wall-clock window). WAL checkpointing runs on the same schedule.

### Matcher (`ExDns.BlackHole.Set`)

* Compiled `%{exact: MapSet, suffixes: MapSet}` keyed by lower-cased trimmed domain.

* `match?(set, qname)` — O(label-count) walk: try the qname itself in `:exact`, then walk up to the apex trying each ancestor in `:suffixes`. Faster than regex; satisfies the 90% of blocklist entries that are plain domains and `*.x.y` wildcards.

* Regex entries (small list) are tried last as a fallback.

* The compiled set lives in `:persistent_term` so the per-query lookup is lock-free. Rebuilds happen out of band from the subscriber.

### List subscriber

`ExDns.BlackHole.Lists.Subscriber` is a GenServer per blocklist. On a configurable schedule (default 24h):

1. Conditional `GET` (If-Modified-Since / ETag) the URL.

2. If 304: bump `last_refresh_unix`, leave compiled set alone.

3. If 200: parse via `ExDns.BlackHole.Lists.Parser` (auto-detects hosts / dnsmasq / AdGuard / plain-domain formats).

4. Update DETS row, request a recompile of the merged set.

Failures are logged + counted but never crash the plugin.

### Query log + telemetry

Listen on the existing `[:ex_dns, :query, :start]` and `[:ex_dns, :query, :stop]` events. On `:stop`, pull the per-query metadata + the policy-decision metadata our hook recorded, write a row to the bounded log, increment the right counters, push an SSE event on the live dashboard.

## API surface

All under the existing `/api/v1/plugins/black_hole`. Read-only:

| Resource | Shape |
|---|---|
| `:overview` | `%{queries_today, blocked_today, percent_blocked, top_queried, top_blocked, top_clients}` |
| `:blocklists` | list of `%{id, url, name, enabled?, last_refresh_unix, last_status, entry_count}` |
| `:allowlist` | list of `%{domain, added_at, by, comment}` |
| `:denylist` | same shape |
| `:groups` | list of `%{id, name, cidrs, blocklist_ids, enabled?}` |
| `:query_log` (paginated) | `%{rows: [...], total, next_cursor}` |

Mutating actions:

| Action | Body | Effect |
|---|---|---|
| `add_blocklist` | `%{url, name?, group_ids?}` | persist + start subscriber |
| `remove_blocklist` | `%{id}` | stop subscriber + drop |
| `refresh_blocklist` | `%{id}` | trigger an immediate fetch |
| `set_blocklist_enabled` | `%{id, enabled}` | toggle without removing |
| `add_allowlist` | `%{domain, comment?}` | persist + recompile |
| `remove_allowlist` | `%{domain}` | persist + recompile |
| `add_denylist` | `%{domain, comment?}` | persist + recompile |
| `remove_denylist` | `%{domain}` | persist + recompile |
| `add_group` | `%{name, cidrs, blocklist_ids}` | persist |
| `remove_group` | `%{id}` | persist |
| `clear_query_log` | `%{}` | truncate the log |
| `disable_for` | `%{seconds}` | bypass the policy hook for N seconds (pi-hole's iconic "disable for 5 minutes" affordance) |

Each action returns the (possibly partial) updated state of the affected resource so the UI can refresh inline without a full reload.

## UI

### Phase 1 — read-only via the generic plugin views

The shipped `PluginTabLive` already supports the `:table` and `:kv` views. With no UI code beyond the existing renderer:

* `/plugins/black_hole` shows the `:overview` (kv) plus `:blocklists` / `:allowlist` / `:denylist` / `:query_log` (tables).

This is enough to validate the policy hook end-to-end.

### Phase 2 — dashboard

A dedicated `DnsUiWeb.BlackHoleLive` module in `dns_ui` (NOT loaded into the server). Adds:

* **Dashboard panel** — donut chart of blocked vs allowed (CSS-only, no JS dep), big numbers for `queries_today` / `blocked_today` / `percent_blocked`, top-N tables for `top_queried` / `top_blocked` / `top_clients`.

* **Live query feed** — subscribes to the `/api/v1/events` SSE stream and prepends each query row.

* **List management** — add / remove / toggle blocklists, allowlist, denylist via `POST /actions/:name` calls.

* **Group editor** — CIDR list + blocklist multi-select.

* **"Disable for N minutes" button** in the navbar.

Wire-up: `PluginTabLive` checks if a plugin-specific module exists in the UI app and delegates to it (`BlackHoleLive` for `slug == "black_hole"`); otherwise falls back to the generic view. This keeps the contract that no plugin code is loaded from the server — the UI module is owned by the UI app.

### Phase 3 — plugin-owned UI fragment

Per the original §5 of the policy/plugins plan, plugins can ship an optional sandboxed server-side-rendered fragment via `GET /api/v1/plugins/:slug/render`. Out of scope for the first cut; mentioned here so the UI module split between Phase 2 and Phase 3 is intentional.

## Configuration

```elixir
config :ex_dns, :black_hole,
  enabled: true,
  storage: {ExDns.BlackHole.Storage.SQLite,
            [path: "/var/lib/exdns/black_hole.sqlite"]},
  default_block_response: :nxdomain,    # | :zero_ip | :refused
  query_log_capacity: 100_000,
  default_subscriber_interval_seconds: 86_400,
  default_blocklists: [
    "https://adaway.org/hosts.txt",
    "https://v.firebog.net/hosts/AdguardDNS.txt"
  ]

config :ex_dns, :plugins, [
  ExDns.BlackHole.Plugin
]
```

Off by default. Operators opt-in by setting `enabled: true` and listing the module under `:plugins`.

## Telemetry

* `[:ex_dns, :black_hole, :match]` — fires on every blocked query: `%{qname, qtype, source_ip, list_id, decision}`.

* `[:ex_dns, :black_hole, :allow]` — fires on every passed query (same metadata, `decision: :allow`).

* `[:ex_dns, :black_hole, :list, :refreshed]` — fires per subscriber cycle: `%{list_id, status, entries}`.

* `[:ex_dns, :black_hole, :compiled]` — fires after a recompile: `%{exact_size, suffix_size, regex_size, ms_taken}`.

The events plug into the existing SSE stream so the UI "flashes" each blocked query in real time.

## Testing

* **`Set` matcher** — property tests on label-walking, exact vs suffix-glob behaviour, regex precedence.

* **Parser** — golden tests covering hosts (`0.0.0.0 ads.com`), dnsmasq (`address=/ads.com/0.0.0.0`), AdGuard (`||ads.com^`), plain-domain, and comment / blank-line handling.

* **Subscriber** — `Req`'s `:plug` adapter feeds canned responses; assert conditional GET (304) skips the parse.

* **Plugin policy hook** — wire a stub `Plugin.Policy` into a real `ExDns.Resolver.Default` and assert `:cont` / `{:halt, ...}` end-to-end.

* **API actions** — POST against the new `actions/:name` route, assert role + scope enforcement.

* **UI** — `BlackHoleLive` receives stubbed API responses via the existing `DnsUi.ApiStub`; assert dashboard renders + the SSE-backed feed updates.

## Sequencing

Build order, each chunk small enough to land + test independently:

1. **Plugin routing table + policy callback** (~3 chunks).

   * `ExDns.Plugin.Policy` + `ExDns.Plugin.Action` behaviours.

   * `ExDns.Plugin.Registry.match/1` + radix-trie route index in `:persistent_term` + `update_routes/2`.

   * `ExDns.Resolver.Plugins` wrapper that does a single `Registry.match/1` per query and dispatches.

2. **Mutation route** (~1 chunk).

   * `POST /api/v1/plugins/:slug/actions/:name` + scope enforcement (`"plugin:" <> slug`) + tests.

3. **BlackHole skeleton** (~3 chunks).

   * `Storage` (DETS shapes) + `Set` (compiled matcher).

   * `Lists.Parser` + `Lists.Fetcher` + `Lists.Subscriber`.

   * `Plugin` module wiring it all together with `routes/0` returning the configured group CIDRs and a stub `policy_resolve/2` returning `:cont` — verifies dispatch end-to-end without yet blocking anything.

4. **Active blocking** (~2 chunks).

   * `policy_resolve/2` consults `Set` + emits telemetry.

   * Allowlist precedence; per-group blocklist selection based on the matched route.
5. **Query log + stats** (~2 chunks).

   * Telemetry handler writing into `Storage`.

   * `:overview` resource builds top-N tables on demand.

6. **API actions** (~2 chunks).

   * `handle_action/2` for every action listed above.

   * Group / CIDR edits call `Registry.update_routes/2` so route-table changes take effect immediately.

   * Auth scope `"plugin:black_hole"` documented + enforced.

7. **UI Phase 1** — read-only via the generic tab (~1 chunk).

   * Plus a `PluginTabLive` extension to delegate to plugin-specific views.

8. **UI Phase 2** — `DnsUiWeb.BlackHoleLive` (~5 chunks).

   * Dashboard, live feed, list management, group editor, disable-for button.

Total: ~19 chunks across the server + UI work.

## Non-goals

* DHCP server. Pi-hole bundles one; we don't.

* Conditional forwarding. We already have per-zone forwarding from Tier B; the BlackHole plugin doesn't replicate it.

* DoH/DoT *for upstream forwarding* — the resolver already has these as listener modes; the plugin doesn't add an upstream-side variant.

* Cosmetic parity with the official pi-hole admin UI. We match the *capabilities* and the operator workflow, not the chart styling.

* Native binary distribution. Pi-hole has its own installer; ExDns ships as Elixir releases.

## Risks / open questions

* **List size at scale.** Common adlist combinations are 500k-2M domains. The compiled `Set` is a pair of `MapSet`s; that's ~50-200 MB resident. Acceptable for a resolver host today, but we should benchmark a 2M-entry set's match latency before committing to the `:persistent_term` approach (it makes a copy on every read; for sets of this size we may want ETS).

* **Recompile cost** when an adlist changes. A 2M-entry rebuild in pure Elixir is roughly 1-2 seconds. Mitigation: run rebuilds in a worker process and swap the `:persistent_term` reference atomically.

* **Route-table size + lookup latency.** A trie keyed on CIDR with a small per-entry filter list is microseconds to walk for hundreds of routes; nobody is going to register hundreds. Document the expected scale (≤ 100 routes per node) and the dispatch budget (≤ 5 µs per query) so future contributors don't optimise prematurely.

* **Overlapping CIDRs across plugins.** Resolved deterministically by longest-prefix → priority → registration order. Surface the resolution in the admin UI's plugin page so operators can see *which* plugin will match a given client IP without guessing.

* **Pass-through invariant.** Any bug in the registry that caused queries with no matching route to be intercepted would silently break unrelated zones. Add a property test that a request matching no route always falls through to the underlying resolver, with a corpus of randomised IPs + qtypes + qnames.

* **Live query feed memory** when a misconfigured client spams. Cap the SSE-side buffer; drop oldest on overflow.

* **Query log write throughput.** A busy resolver can sustain tens of thousands of qps; per-query SQLite inserts on the hot path would pin the writer. Buffer query-log appends in-process (a small ring) and flush in batches every N ms — the writer becomes one transaction per batch, not per query. The reader path stays unaffected because SQLite WAL allows concurrent reads.

* **Single-node SQLite vs cluster.** The default backend is per-node by design; an HA deployment needs the Postgres or Khepri adapter (deferred). Document this clearly so operators don't assume the SQLite file is replicated.

## Out-of-scope follow-ups

* Per-client *per-domain* allow / block (pi-hole's "client group" feature, but at the domain level). Builds naturally on the groups table once the basics ship.

* DNSSEC validation passthrough. Pi-hole today returns its own NXDOMAIN which strips RRSIG; we should make the block response pi-hole-compatible OR offer a "soft block" mode (NXDOMAIN with the original RRSIG). Decision deferred until we have a real user.

* Multi-node sharing of allowlists / denylists / groups. Today the DETS file lives per-node; a clustered build will need either a Khepri backend or a leader-elected primary.
