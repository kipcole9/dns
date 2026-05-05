# Web UI, policy framework, plugin architecture, BIND comparison

**Date:** 2026-05-05
**Status:** Plan only — no implementation work yet
**Touches:** new web app, `ExDns.Policy`, `ExDns.Plugin` (new),
existing anycast policy, BIND feature gap analysis

This document plans six related pieces of work. They are
sequenced so each later piece builds on the earlier ones, but
each section is self-contained — an implementer can start any
section after its declared prerequisites.

## Table of contents

1. [Web UI for server + zone management](#1-web-ui-for-server--zone-management)
2. [Enhanced policy mechanism](#2-enhanced-policy-mechanism)
3. [DNS plugin framework](#3-dns-plugin-framework)
4. [Reimplement anycast as a plugin](#4-reimplement-anycast-as-a-plugin)
5. [Plugin UI tabs](#5-plugin-ui-tabs)
6. [BIND parity gap analysis](#6-bind-parity-gap-analysis)

---

## 1. Web UI for server + zone management

### Goals

* **Operate the server**: live status, listener bindings, DNSSEC
  key state, secondary-zone health, IXFR journal browser, RRL
  decisions, drain controls.
* **Manage zones**: list zones, edit records inline, validate +
  bump SOA serial, sign / re-sign, view the journal of changes.
* **Trigger lifecycle actions**: reload zones, force AXFR on a
  secondary, prepare/complete/purge ZSK or KSK rollover, rotate
  TSIG keys.
* **Observe**: query rate by qtype/transport/rcode, RRL drops,
  cache hit rate, DNSSEC validation outcomes — all already wired
  through telemetry; the UI just renders.

The UI is **not** a config writer for `runtime.exs` — production
config still lives in files. The UI mutates *runtime* state
(zone records, key states, transfer triggers) and reads
observability data.

### Registrar/DNS-host UI survey

I surveyed the major DNS-management UIs:

| Provider | Strengths | Weaknesses |
|---|---|---|
| **Cloudflare** | Inline edit on every cell, fast keyboard nav, dark mode, very clean typography, batched edits, audit log, JSON-import for zone files | Locks you into their nameservers |
| **DNSimple** | Clean, focused, good per-record validation, nice ALIAS/POOL UX | Limited bulk-ops, fewer integrations |
| **Route 53** | Powerful (geolocation, latency, weighted), strong API parity | UI is functional rather than pleasant |
| **NS1** | Best-in-class for traffic-steering policies | Enterprise complexity throughout |
| **Hetzner DNS** | Minimalist, fast, fair pricing | No DNSSEC UI, basic bulk-edit |
| **DigitalOcean** | Approachable for new users | Few advanced features, no DNSSEC UI |
| **Vercel Domains** | Great defaults, very polished | Thin feature set |
| **Hover** | Friendly, simple | Underpowered for serious DNS work |
| **Gandi** | Capable, registrar-side LiveDNS | UI feels dated |

**Recommendation: model the UI on Cloudflare's DNS dashboard.**
It's the most widely-used DNS UI on the planet — most operators
have muscle memory for it — and it gets the fundamentals right:

* One row per record, inline edit on every column, keyboard
  shortcuts for add/edit/delete.
* The "domain card" entry surface for picking a zone, then a
  single records table for the chosen zone.
* Clear filter chips above the table (record type, search by
  name/value).
* Edit-then-save discipline rather than auto-commit — fewer
  accidental publishes.
* Built-in DNSSEC state panel with the apex DS values rendered
  ready-to-paste.
* Dark mode that's actually pleasant to use, not just inverted.

Where we should **diverge** from Cloudflare:

* **Built-in observability**. We already emit telemetry; expose
  query rate / RRL / cache hit / DNSSEC validation as first-class
  panels under each zone. Cloudflare has Analytics; ours is
  free.
* **Surface the IXFR journal**. Show every serial bump as a
  scrollable timeline of `{added, removed}` per change.
* **Plugin tabs** (see §5). Cloudflare has no extension
  surface; ours does.
* **Multi-server status banner**. We're a real cluster (libcluster
  + partisan), so the top-of-page banner shows which nodes are
  up + which is the update master.

### Architecture — UI is a *client* of the DNS server

**Hard requirement (decided 2026-05-05):** The web UI is a
**separate, independently runnable application** that talks to
the DNS server only over a well-specified, versioned HTTP API.
The UI must be able to:

* run on a different machine, in a different container, in a
  different release, on a different deploy cadence;
* run against a remote DNS server it has no compile-time
  dependency on;
* run against multiple servers (a development server today,
  a production cluster tomorrow) without rebuilding;
* be replaced — by a different UI, a CLI, an Ansible
  playbook, an internal admin portal — without changing the
  server.

That rules out the original "sibling Phoenix umbrella in the
same BEAM" plan. Instead:

```
~/Development/dns/
  ex_dns/                      ← existing library (unchanged)
    priv/openapi/v1.yaml       ← FORMAL API CONTRACT (new)
    lib/ex_dns/admin/          ← REST surface implementing the contract
      router.ex                ← Plug.Router; existing Admin extended
      auth.ex
      events.ex                ← SSE stream for live updates

~/Development/dns_ui/          ← SEPARATE Mix project (own repo)
  mix.exs                      ← does NOT depend on :ex_dns
  lib/ex_dns_ui/
    endpoint.ex
    router.ex
    api_client.ex              ← typed client generated from openapi/v1.yaml
    live/
      zones_live.ex
      zone_live.ex
      keys_live.ex
      secondaries_live.ex
      observability_live.ex
    components/
      core_components.ex
      layouts.ex
      layouts/
        app.html.heex          ← <Layouts.app> wrapper
      primitives/
        stack.ex               ← every-layout.dev primitives
        cluster.ex
        sidebar.ex
        box.ex
      records_table.ex
      record_row.ex
      plugin_tab.ex            ← see §5
```

The UI app is its own release. Operators run it next to the DNS
server, on a separate host, or behind a proxy that routes
`/admin` → DNS server and `/` → UI. Either layout is supported
because the API contract is the only coupling.

### The formal API contract

The API surface lives in **`ex_dns/priv/openapi/v1.yaml`** as an
OpenAPI 3.1 document. It is the authoritative spec — both the
server (`ExDns.Admin.Router`) and the UI (`ExDns.UI.ApiClient`)
are derived from it (or checked against it in CI).

* **Versioned**: every URL is prefixed `/api/v1`. Breaking
  changes cut a new major (`/api/v2`); additive changes do not.
* **JSON over HTTP**: responses are JSON; no XML, no protobuf
  on this surface. (dnstap / Prometheus stay on their own
  dedicated endpoints.)
* **Bearer-token auth on every endpoint** — no anonymous reads.
  The token is provisioned at server startup; the UI prompts
  the operator for it on first connect and stores it in a
  cookie.
* **Live updates via Server-Sent Events** at
  `GET /api/v1/events` — one event stream covering zone
  reloads, secondary state changes, plugin registry changes,
  RRL decisions, and DNSSEC key rollover stage transitions.
  Each event has `type`, `timestamp`, and a `data` object whose
  shape is also in the OpenAPI document.
* **No RPC, no `:erpc`, no shared ETS** between the two apps.
  Everything the UI does, the API can do — which means
  everything the UI does, a `curl` user can do too.

#### v1 endpoint inventory

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/server` | Server identity (NSID), version, listener bindings, cluster nodes |
| `GET` | `/api/v1/zones` | List zones with apex, serial, source path, kind (primary/secondary/catalog) |
| `GET` | `/api/v1/zones/:apex` | Zone metadata + counts by record type |
| `GET` | `/api/v1/zones/:apex/records` | Paginated record listing with type/name filters |
| `POST` | `/api/v1/zones/:apex/records` | Add records (atomic; bumps SOA serial) |
| `PATCH` | `/api/v1/zones/:apex/records/:id` | Edit one record |
| `DELETE` | `/api/v1/zones/:apex/records/:id` | Delete one record |
| `POST` | `/api/v1/zones/:apex/reload` | Re-read zone file from disk |
| `GET` | `/api/v1/zones/:apex/journal` | Paginated journal of `{added, removed}` per serial bump |
| `POST` | `/api/v1/zones/:apex/notify` | Trigger refresh (secondaries only) |
| `GET` | `/api/v1/secondaries/:apex` | Secondary state machine snapshot |
| `GET` | `/api/v1/keys` | DNSSEC key inventory (per zone, per role, state) |
| `POST` | `/api/v1/keys/:id/rollover/:phase` | Advance rollover state (prepare/active/retire/purge) |
| `GET` | `/api/v1/plugins` | Plugin registry — slug, node, version, healthy?, UI metadata |
| `POST` | `/api/v1/plugins/:slug/disable` | Disable a registered plugin |
| `POST` | `/api/v1/plugins/:slug/enable` | Re-enable a disabled plugin |
| `GET` | `/api/v1/metrics/summary` | Time-bucketed query rate, RRL drops, cache hit ratio, validation outcomes |
| `GET` | `/api/v1/events` | Server-Sent Events stream (live updates) |
| `GET` | `/api/v1/health` | Liveness probe (proxies `ExDns.Health`) |
| `GET` | `/api/v1/ready` | Readiness probe |

Existing `/admin/*` routes from `ExDns.Admin` move under
`/api/v1/...` as part of the contract bring-up; legacy paths
get a deprecation warning header for one minor version, then
are removed.

#### CI guarantees

* `mix exdns.openapi.check` runs on every PR — fails if the
  router's actual surface drifts from `priv/openapi/v1.yaml`.
* `mix exdns.openapi.client` regenerates the typed client used
  by `ex_dns_ui` from the spec; the regenerated file is
  committed and CI fails if it would change.
* The contract is the source of truth; both server and UI are
  downstream of it.

### UI tech stack

Phoenix v1.8 + LiveView. Tailwind v4 (no `tailwind.config.js`).
No daisyUI — handcrafted components per the project standard.
Match the conventions in `~/Development/image/image_playground/AGENTS.md`
exactly:

* Every LiveView template starts with `<Layouts.app flash={@flash} ...>`
* `<.icon name="hero-x-mark" class="…" />` for icons
* `<.input>` from `core_components` for form inputs
* `app.css` uses the `@import "tailwindcss" source(none); @source ...`
  syntax
* No `@apply`, no inline `<script>`, no external vendor `<link>`

### Apply every-layout.dev rudiments

Per <https://every-layout.dev/rudiments/boxes/> we **ban margin**
on components and use composable layout primitives. Build a
small primitives library at `lib/ex_dns_web/components/primitives/`:

* **Box** — single owns-its-padding container; the only thing
  that has internal whitespace.
* **Stack** — vertical rhythm via `gap`, never margin.
* **Cluster** — horizontal flex with wrap, gap-spaced (used for
  filter chips, button groups).
* **Sidebar** — two-column with a fixed-width sidebar and a
  fluid main, collapsing under a configurable threshold.
* **Cover** — full-viewport hero (used by the empty-state
  zones screen).
* **Switcher** — auto-switches from horizontal to vertical
  layout based on container width.
* **Center** — horizontal centering with a max-width.

Each primitive is a stateless functional component
(`def stack(assigns)`) that emits a single semantic element with
the layout style locked on. Components NEVER set their own
external margin — they sit inside a primitive that owns the
spacing.

### Light + dark mode

Tailwind v4 ships native support via the `dark:` variant + the
`color-scheme` system preference. Plan:

* CSS custom properties for every semantic token
  (`--color-surface`, `--color-text`, `--color-border`,
  `--color-accent`, `--color-warn`, `--color-error`).
* Two `:root` blocks — one for `prefers-color-scheme: light`,
  one for `prefers-color-scheme: dark`.
* A `data-theme="light|dark|system"` attribute on `<html>` so
  users can override the OS preference. The toggle persists to
  `localStorage` via a tiny `app.js` hook (~10 lines, the only
  client-side code we ship).
* Every Tailwind class uses the semantic token via `bg-[var(--color-surface)]`
  etc., NOT hardcoded `bg-slate-50` / `dark:bg-slate-950`.
  Easier to retheme, easier to audit contrast.
* Both themes pass WCAG AA contrast for normal text against
  surface and accent against surface.

### Screens

Five top-level routes, all LiveView:

| Route | LiveView | Purpose |
|---|---|---|
| `/` | `ZonesLive` | Pick a zone (or "+ New") |
| `/zones/:apex` | `ZoneLive` | Records table + per-zone observability |
| `/keys` | `KeysLive` | DNSSEC keys + rollover wizard |
| `/secondaries` | `SecondariesLive` | Secondary-zone state board |
| `/observability` | `ObservabilityLive` | Cluster-wide metrics |
| `/plugins/:slug` | `PluginTabLive` | Plugin-provided UI (§5) |

`ZoneLive` is the workhorse — Cloudflare-style records table:

* Columns: type, name, value, TTL, proxy?-style toggle for any
  per-record policy flags, RRSIG state, last-modified.
* Inline edit on every cell with optimistic save; commit on
  blur or `Cmd-Return`.
* Filter chips: type-multi-select, free-text search across
  name + value.
* Sticky header, virtualised body for zones with thousands of
  records.
* "+ Add record" opens a modal Stack of inputs.
* Bulk operations: select rows → delete / change TTL / re-sign.
* Below the table: timeline of journal entries (added /
  removed lists per serial bump, expandable).
* Right rail: per-zone observability — query rate, top qnames
  this zone served, RRL drops affecting this zone.

### Authn / authz

Authentication is **mandatory** in the client/server split —
the API is no longer same-process. Two layers:

1. **Server-side auth on the API.** The `/api/v1/*` surface
   requires `Authorization: Bearer <token>` on every request.
   Tokens are provisioned via `mix exdns.token.issue --role
   <role> --scopes <zone-globs>`, written to a server-local
   keystore. Roles are `viewer / zone_admin / cluster_admin`,
   scoped per-zone-glob. The server enforces the role at the
   route handler — the UI never sees a token it isn't allowed
   to act on.

2. **UI-side session.** The UI app prompts for the bearer
   token on first connect, stores it in an HttpOnly cookie,
   and attaches it to every API call. The UI itself does not
   maintain user accounts in v1; it is a thin "remote control"
   for tokens issued by the server.

For zero-trust networks, the UI app sits behind a TLS proxy
(Cloudflare Access, Tailscale, Pomerium) that handles human
auth — the bearer token then carries the *role*, not the
identity. v2 adds first-class user accounts in the UI with
`mix phx.gen.auth`, mapping users to one or more server tokens.

The DNS server's `:ex_dns, :admin, [bind: ...]` setting
controls where the API listens. Localhost-only is the default;
operators who run the UI on a different host must explicitly
open the API to that host's IP.

### Phasing

* **Phase 0 — API surface.** Cut `priv/openapi/v1.yaml`,
  implement read-only routes (`/server`, `/zones`,
  `/zones/:apex/records`, `/keys`, `/secondaries`,
  `/metrics/summary`, `/events`, `/health`, `/ready`). Ship
  the OpenAPI doc, the bearer-token issuer, the SSE stream.
  No UI yet — operators can drive the API with `curl`.
* **Phase 1 — read-only UI.** `ex_dns_ui` Mix project.
  ZonesLive + ZoneLive in display-only mode. SecondariesLive.
  Observability dashboards. Consumes only the v1 API.
* **Phase 2 — record edits API + UI.** Add the mutating
  routes (`POST/PATCH/DELETE` on records, `POST /reload`).
  UI gets inline edit, add, delete on the records table.
  Mutations go through the existing `Storage.put_zone/2`
  inside the server, so journal + outbound NOTIFY fire
  automatically.
* **Phase 3 — DNSSEC + secondaries.** Add `/keys/*/rollover/*`
  routes. UI's KeysLive gets the rollover wizard,
  SecondariesLive gets the force-AXFR button.
* **Phase 4 — plugins.** §5 wiring (revised below to fit the
  client/server model).

---

## 2. Enhanced policy mechanism

### What we have today

`ExDns.Policy` is already a behaviour with `init/1` + `resolve/2`,
slotted into `ExDns.Resolver.Policy` as a chain that runs each
policy in order until one returns `{:halt, response}`. Today
there's exactly one in-tree policy (`ExDns.Policy.SourceIp`) and
its job overlaps with what an "anycast plugin" would do.

### What's missing for plugin-grade richness

1. **No phase model.** Right now every policy is a "halt or
   continue" stage. That can't express:
   * "rewrite the qname before resolution" (DNAME-style)
   * "post-process the resolver's answer before sending"
     (filter responses by client class, e.g. pi-hole)
   * "reject this query entirely with REFUSED"
2. **No async policies.** Some plugins will need to consult an
   external service (a blocklist API, an ML model, a downstream
   DNS server). The chain needs to be able to await a reply
   without blocking the worker.
3. **No metadata threading.** A policy that classifies the
   client (e.g. "this is a kids profile") needs to communicate
   that to later policies. We have no scratchpad.
4. **No live reconfiguration.** Today policies are baked at
   `Application.start/2`. We need to add/remove/reorder at
   runtime without restart.

### Target shape

Replace the `:continue | {:halt, response}` callback with a
**three-phase pipeline**:

```
                    ┌────────────────┐
  request bytes →   │  :decode hook  │ ─→ may rewrite the parsed Message
                    └────────────────┘
                              │
                              ▼
                    ┌────────────────┐
                    │ :pre_resolve   │ ─→ may halt with response, or
                    │   policies     │    continue with maybe-modified
                    └────────────────┘    request
                              │
                              ▼
                    ┌────────────────┐
                    │   resolver     │ ─→ Default / Hybrid / Forwarder
                    └────────────────┘
                              │
                              ▼
                    ┌────────────────┐
                    │ :post_resolve  │ ─→ may transform the answer
                    │   policies     │    (filter, redirect, log)
                    └────────────────┘
                              │
                              ▼
                       wire response
```

Each policy declares **which phases it participates in** + an
ordered priority within that phase.

### New behaviour

```elixir
defmodule ExDns.Policy do
  @callback init(opts :: keyword()) :: {:ok, state :: term()} | {:error, term()}

  @callback phases() :: [:pre_resolve | :post_resolve | :decode]

  @callback priority() :: integer()       # lower = earlier

  @callback handle_pre_resolve(
              request :: ExDns.Request.t(),
              scratch :: map(),
              state :: term()
            ) ::
              {:cont, ExDns.Request.t(), map()}
              | {:halt, ExDns.Message.t()}
              | {:error, term()}

  @callback handle_post_resolve(
              request :: ExDns.Request.t(),
              response :: ExDns.Message.t(),
              scratch :: map(),
              state :: term()
            ) :: {:cont, ExDns.Message.t(), map()}

  @optional_callbacks handle_pre_resolve: 3, handle_post_resolve: 4,
                      priority: 0
end
```

The `scratch` map is the per-request scratchpad. Earlier
policies write to it (`Map.put(scratch, :client_profile, :kids)`)
and later policies read from it.

### Async policies

An asynchronous policy returns `{:async, ref, continuation_fn}`
from `handle_pre_resolve/3`. The pipeline runner:

1. Spawns a `Task.async` that runs `continuation_fn` (typically
   makes an HTTP call).
2. Suspends the request (worker checks back in to the pool).
3. When the Task replies, the worker resumes the pipeline at
   the next policy.

Bounded by a global `:policy, [async_timeout: 1_000]` so a slow
external policy can't block forever.

### Live reconfiguration

A new `ExDns.Policy.Registry` GenServer owns the ordered list
of installed policies for each phase. Public API:

```elixir
ExDns.Policy.Registry.install(MyPolicy, opts, phase: :pre_resolve, priority: 50)
ExDns.Policy.Registry.uninstall(MyPolicy)
ExDns.Policy.Registry.enable(MyPolicy)
ExDns.Policy.Registry.disable(MyPolicy)
ExDns.Policy.Registry.list()
```

Stored in `:persistent_term` on every change so the resolver
worker reads it lock-free on each query. The Registry persists
its current list to disk (`:dets` or a config snapshot file)
so restarts survive.

### Telemetry

Each phase emits `[:ex_dns, :policy, :phase, :start | :stop]`
with `%{policy: module, phase: atom, halted?: boolean}`. The
admin UI's per-zone observability panel surfaces "this query
was halted by `MyPolicy` in `:pre_resolve`" for live debugging.

### Migration

The current `ExDns.Resolver.Policy` chain is replaced. The
existing `ExDns.Policy.SourceIp` becomes a converter target
in §4 — it'll port to a plugin rather than stay as a built-in
policy.

---

## 3. DNS plugin framework

### Why plugins should be separate nodes

A plugin doing pi-hole-style filtering may pull a 200K-entry
blocklist into memory, do tens of thousands of qname-set
lookups per second, and load a refresh cron. We don't want
that footprint inside the DNS server's own BEAM:

* **Memory isolation**: a runaway plugin can't crowd out the
  resolver's worker pool or the recursor cache.
* **Crash isolation**: plugin code is by definition extension
  code we may not have written ourselves. A plugin crash
  must not take the resolver down.
* **Independent restart**: hot-reload a plugin's code without
  interrupting the resolver.
* **Independent scaling**: pin the plugin to its own
  hardware / container; restart frequency / memory limits
  per plugin.

So plugins are **separate Erlang nodes**, joined to the
resolver cluster via libcluster (we already use it). They are
discovered + reconnected automatically.

### Lifecycle

```
       PLUGIN NODE                              RESOLVER NODE(S)
       ───────────                              ────────────────

  start ───────────► register(metadata) ───────►  ExDns.Plugin.Registry
                                                       │
                       ◄──── :registered ────          │
                                                       │
                   poll for resolver up/down events    │
                       ◄──── {:resolver_up, node} ─────┤
                       ◄──── {:resolver_down, node} ───┤
                                                       │
                       ──── add_route(cidr, qtype) ────►│
                                                       │
                                              for each matching query
                       ◄──── {:resolve, request, ref}──┤
                       ──── {:resolve_reply, ref, …} ─►│
                                                       │
       stop ────────► unregister() ──────────────►     │
                                                       │
       (sudden death) detected via :nodedown          │
                                                       │
```

Two libcluster topologies — the resolver cluster, and a
"plugins" cluster. They overlap.

### Plugin behaviour

```elixir
defmodule ExDns.Plugin do
  @moduledoc """
  Behaviour every DNS plugin implements.

  A plugin runs on its own node and registers with the
  resolver cluster. The resolver dispatches matching queries
  to the plugin and waits for a synchronous reply (with a
  bounded timeout) per the plugin's declared SLA.
  """

  @callback metadata() :: %{
              name: binary(),                # human-readable
              slug: atom(),                  # url-safe id
              version: binary(),
              # Default reply timeout in ms; pipeline halts
              # request if exceeded.
              sla_ms: pos_integer(),
              # UI tab declaration (§5)
              ui: nil | %{module: module(), title: binary()}
            }

  @callback routes() :: [
              %{
                cidrs: [{:inet.ip_address(), 0..128}],
                qtypes: [atom()] | :any,
                # Earlier-priority plugins see the request first.
                priority: integer()
              }
            ]

  @callback handle_query(
              request :: ExDns.Plugin.Request.t(),
              state :: term()
            ) ::
              {:reply, ExDns.Plugin.Reply.t(), term()}
              | {:passthrough, term()}        # let resolver handle normally
              | {:refuse, term()}             # rcode 5
              | {:nxdomain, ExDns.Resource.SOA.t() | nil, term()}

  @callback handle_resolver_up(node(), state :: term()) :: term()
  @callback handle_resolver_down(node(), state :: term()) :: term()

  @optional_callbacks handle_resolver_up: 2, handle_resolver_down: 2
end
```

### Request + reply structs

Crossing the node boundary needs serialisable structs — not
opaque PIDs:

```elixir
defmodule ExDns.Plugin.Request do
  defstruct [
    :id,                 # request id (matches reply ref)
    :qname,              # binary, lower-case, trailing-dot-stripped
    :qtype,              # atom
    :qclass,             # :in
    :source_ip,          # tuple
    :source_port,
    :transport,          # :udp | :tcp | :doh | :dot | :doq
    :scratch,            # the policy scratch map (read-only here)
    :received_at         # System.os_time(:microsecond)
  ]
end

defmodule ExDns.Plugin.Reply do
  @moduledoc """
  The standardized reply shape every plugin must produce.
  Decoded into the response Message by the resolver.
  """
  defstruct [
    :rcode,              # 0 NOERROR | 3 NXDOMAIN | 5 REFUSED | …
    :answer,             # [%ExDns.Resource.A{} | …]
    :authority,
    :additional,
    :ttl_override,       # optional clamp on every record's TTL
    :extra_metadata      # surfaced in telemetry
  ]
end
```

### `ExDns.Plugin.Registry`

A `GenServer` running on the resolver cluster. State:

```elixir
%{
  plugins: %{
    plugin_slug => %{
      node: node(),                  # where it lives
      metadata: %{…},
      routes: [%{cidr, qtypes, priority}],
      enabled?: boolean,
      monitor_ref: reference()
    }
  },
  # Per-route lookup index, rebuilt whenever plugins change.
  # Scanned on every query hit so it MUST be fast.
  route_index: ...
}
```

Public API:

```elixir
ExDns.Plugin.Registry.register(slug, node, metadata, routes)
ExDns.Plugin.Registry.unregister(slug)
ExDns.Plugin.Registry.enable(slug)
ExDns.Plugin.Registry.disable(slug)
ExDns.Plugin.Registry.update_routes(slug, routes)  # plugin-driven
ExDns.Plugin.Registry.lookup(source_ip, qtype) :: nil | %{slug: …, node: …}
ExDns.Plugin.Registry.list() :: [%{slug, metadata, enabled?, healthy?}]
```

The registry monitors each plugin node. On `:nodedown`:

* The plugin's routes are removed from the index immediately.
* Plugin marked `healthy?: false` until re-registration.
* In-flight requests targeting that plugin are abandoned →
  the resolver falls through to the next-priority plugin or to
  the underlying resolver.

The registry's snapshot lives in `:persistent_term` so the
worker reads it lock-free.

### Wiring into the policy pipeline

The plugin dispatch is implemented as a single built-in policy
in the `:pre_resolve` phase, `priority: 0` (runs first):

```elixir
defmodule ExDns.Policy.PluginDispatch do
  @behaviour ExDns.Policy

  def init(_), do: {:ok, %{}}
  def phases, do: [:pre_resolve]
  def priority, do: 0

  def handle_pre_resolve(request, scratch, _state) do
    case ExDns.Plugin.Registry.lookup(request.source_ip, request.message.question.type) do
      nil ->
        {:cont, request, scratch}

      %{slug: slug, node: node, sla_ms: sla} ->
        # Synchronous send via :erpc with the plugin's declared SLA.
        case dispatch_to_plugin(node, slug, request, sla) do
          {:reply, reply}     -> {:halt, build_response(request, reply)}
          {:refuse, _}        -> {:halt, refused_response(request)}
          {:nxdomain, soa, _} -> {:halt, nxdomain_response(request, soa)}
          {:passthrough, _}   -> {:cont, request, scratch}
          {:error, _reason}   -> {:cont, request, scratch}  # fail-open
        end
    end
  end
end
```

### Hot-add / hot-remove without downtime

Three independent paths for "the resolver should never go down":

1. **Cluster-driven**: a new plugin node joins → libcluster
   detects it → it sends `register(...)` → registry adds it
   → next query is dispatched to it. No resolver restart.

2. **Admin-API-driven**: operator hits
   `POST /admin/plugins/:slug/disable` → registry flips the
   flag → next query bypasses the plugin. No restart.

3. **Plugin-driven self-update**: the plugin updates its own
   routes via `update_routes(slug, new_routes)` (e.g. blocklist
   refreshed; CIDR list now bigger). Registry rebuilds the
   route index. No restart.

Plugin code reload is by replacing the *node*, not the *code
on the node*: stop the old node, start a new one with the
fresh release. The registry sees `:nodedown` then re-register
on join. Failover is handled by next-priority plugins or the
underlying resolver.

### Telemetry

* `[:ex_dns, :plugin, :registered | :unregistered | :enabled | :disabled]`
* `[:ex_dns, :plugin, :dispatch, :start | :stop | :timeout]`
  with `%{plugin: slug, decision: :reply | :passthrough | :refuse | :nxdomain | :error}`

The Plugin tab in the UI (§5) consumes these.

---

## 4. Reimplement anycast as a plugin

The existing `ExDns.Policy.SourceIp` already does
"per-CIDR-route synthetic answers" — exactly the shape of an
anycast plugin. Migrate it from a built-in policy to a
first-party plugin under a new sibling app:

```
~/Development/dns/
  ex_dns/
  ex_dns_web/
  ex_dns_anycast/             ← new sibling
    lib/ex_dns_anycast/
      application.ex          ← starts on its own node
      plugin.ex               ← @behaviour ExDns.Plugin
      config.ex               ← reads :ex_dns_anycast config
      ui_live.ex              ← UI tab (§5)
```

### Plugin shape

```elixir
defmodule ExDns.Anycast.Plugin do
  @behaviour ExDns.Plugin

  @impl true
  def metadata do
    %{
      name: "Anycast routing",
      slug: :anycast,
      version: "0.1.0",
      sla_ms: 5,                # synth-only, very fast
      ui: %{module: ExDns.Anycast.UILive, title: "Anycast"}
    }
  end

  @impl true
  def routes do
    Application.get_env(:ex_dns_anycast, :table, [])
    |> Enum.map(fn {cidr, _answers} ->
      %{cidrs: [cidr], qtypes: :any, priority: 50}
    end)
  end

  @impl true
  def handle_query(%ExDns.Plugin.Request{} = req, state) do
    case match_cidr(req.source_ip, state.table) do
      nil ->
        {:passthrough, state}

      answers ->
        case Map.get(answers, req.qtype) do
          nil ->
            {:passthrough, state}

          synthetic ->
            reply = %ExDns.Plugin.Reply{
              rcode: 0,
              answer: build_answer(req, synthetic),
              authority: [],
              additional: []
            }

            {:reply, reply, state}
        end
    end
  end
end
```

### Migration steps

1. Create `ex_dns_anycast` sibling app (umbrella sibling, not
   nested under `ex_dns`).
2. Copy `ExDns.Policy.SourceIp` logic into
   `ExDns.Anycast.Plugin.handle_query/2` — the per-CIDR table
   format stays identical so existing operator config still
   parses.
3. Have the plugin's `Application.start/2` call
   `ExDns.Plugin.Registry.register/4` against the resolver
   cluster.
4. Remove `ExDns.Policy.SourceIp` from the `ex_dns` codebase.
5. Update CHANGELOG: anycast is now a plugin in its own
   release; `:ex_dns_anycast` dep is required if you want
   anycast routing.

### Why the migration is safe

* The plugin runs on a separate node by design — failure of the
  anycast plugin does not break the resolver. Today, a SourceIp
  policy crash *does* take the worker down.
* Per-CIDR config moves from `:ex_dns, :policies` to
  `:ex_dns_anycast, :table` — clearer ownership.
* Zero protocol change for downstream operators: the wire
  responses are bit-identical to what `SourceIp` would have
  produced.

---

## 5. Plugin UI tabs

### Revised goal (consistent with §1's client/server model)

A plugin can expose a tab in the UI, but **without** loading
plugin code into the UI app's BEAM and **without** the UI
holding any direct handle to the plugin node. The UI is a pure
client of the DNS server's API; the DNS server is a pure client
of plugin nodes via `ExDns.Plugin.Registry`. Plugin UI tabs
flow through that same chain:

```
   browser ──► ex_dns_ui ──► /api/v1/* on DNS server ──► plugin node
                                       (HTTP + SSE)             (:erpc)
```

### How it works (client/server-friendly)

1. **Plugin declares its UI surface in metadata**:

   ```elixir
   ui: %{
     slug: :anycast,
     title: "Anycast",
     # one or more API resources the plugin exposes via its
     # registered DNS-server API extension (below).
     resources: [:routes, :hits]
   }
   ```

   No module reference, no BEAM coupling.

2. **DNS server proxies plugin data over the formal API**:
   the registry exposes one route per plugin under
   `/api/v1/plugins/:slug/...`. Calls into a plugin's API are
   forwarded to that plugin's node via `:erpc` (with the
   plugin's declared SLA). Responses are JSON, schema-checked
   against the OpenAPI fragment the plugin contributed.

3. **Plugin contributes an OpenAPI fragment**: each plugin
   ships an `openapi.yaml` describing its `:resources`. At
   registration time, the registry merges that fragment into
   the live `/api/v1` spec under `/plugins/{slug}/...`. The
   merged spec is what `mix exdns.openapi.check` validates.

4. **UI discovers plugin tabs from the API**:
   `GET /api/v1/plugins` returns each plugin's `ui` metadata.
   The UI's nav iterates that list and builds tabs with
   `live_path("/plugins/" <> slug)`. No code is loaded from
   the plugin into the UI.

5. **Tab UI is rendered by ex_dns_ui itself**: the UI ships a
   small set of generic plugin views (table, key/value, time
   series, log). The plugin's `ui` metadata picks which one to
   use and binds it to its `:resources`. A plugin author writes
   *no* LiveView code — they expose JSON, the UI renders it.

   v2 adds an opt-in escape hatch: a plugin may publish a
   server-side-rendered fragment via
   `GET /api/v1/plugins/:slug/render` that the UI embeds inside
   the layout. The fragment is sandboxed (CSP, no script
   execution) and is opt-in per deployment.

### Constraints on plugin tabs

* Plugin data is JSON over the API; no BEAM-side coupling
  between the plugin and the UI.
* Each plugin's API surface is bounded by its OpenAPI
  fragment — anything not in the fragment is a 404.
* The DNS server enforces the bearer token's role on plugin
  routes the same way it does on its own routes.

### Hot install / hot remove

When a plugin node joins the cluster, registers, and declares
UI metadata:

* The DNS server's SSE stream (`/api/v1/events`) emits a
  `plugin.registered` event with the slug and merged OpenAPI
  fragment.
* Connected UI clients re-fetch `GET /api/v1/plugins` and
  rebuild the nav. New tab appears within seconds.
* When the plugin node leaves: SSE emits `plugin.unregistered`;
  the UI removes the tab; clients on its page redirect to `/`
  with a flash.

### Versioning

* Plugin metadata declares its OpenAPI fragment's version.
* The registry refuses to merge a fragment whose `openapi`
  major version disagrees with the server's.
* Mismatches surface in `GET /api/v1/plugins` so operators see
  the unhealthy plugin in the UI's "Plugins" page.

### What's NOT supported (deliberately)

* Plugin-supplied raw HTML / arbitrary JS in v1 (security +
  theming). The opt-in v2 escape hatch is sandboxed.
* Plugins loading code into the UI app's BEAM. Ever. The UI
  has zero compile-time or runtime dependency on plugin code.
* Plugin-supplied static assets in v1 — inline as data URLs
  or serve from the plugin's own HTTP endpoint. v2 adds an
  asset proxy through the DNS server's API.

---

## 6. BIND parity gap analysis

Goal: identify any feature whose absence would block a typical
BIND operator from migrating to ExDns. Categorise each item as:

* ✅ **Already in ExDns**
* ⚠️ **Partial / different shape but functionally available**
* 🟥 **Showstopper** — operator can't migrate without it
* 🟡 **Important** — most ops will need it eventually
* 🟦 **Niche** — defensible to skip for v1

### What we already match

| BIND feature | ExDns equivalent | Status |
|---|---|---|
| Authoritative serving | `ExDns.Resolver.Default` + Storage | ✅ |
| Recursive resolver | `ExDns.Resolver.Hybrid` + iterator | ✅ |
| Forwarder mode | `ExDns.Resolver.Forwarder` | ✅ |
| AXFR / IXFR | full + journal-backed | ✅ |
| NOTIFY (in + out) | `ExDns.Notify` + receiver | ✅ |
| TSIG | `ExDns.TSIG` (sign + verify, both directions) | ✅ |
| DNSSEC validation | `ExDns.DNSSEC.Validator` (full chain) | ✅ |
| DNSSEC signing | ZSK + KSK; ECDSA/Ed25519 | ✅ |
| NSEC + NSEC3 chain (signing) | `ExDns.DNSSEC.NSEC3.Chain` | ✅ |
| RFC 8198 aggressive NSEC | iterator-wired | ✅ |
| KSK rollover (CDS/CDNSKEY) | `ExDns.DNSSEC.Rollover` | ✅ |
| Catalog zones | `ExDns.Zone.Catalog` + applier | ✅ |
| RRL | `ExDns.RRL` | ✅ |
| DNS Cookies | `ExDns.Cookies` | ✅ |
| EDNS0 + EDNS Padding | `ExDns.Resource.OPT` + `ExDns.EDNSPadding` | ✅ |
| EDNS Client Subnet | `ExDns.EDNSClientSubnet` | ✅ |
| RFC 2308 negative caching | `ExDns.Recursor.Cache` | ✅ |
| QNAME minimisation | `ExDns.Recursor.QnameMinimisation` | ✅ |
| Query name + type ACLs | `ExDns.Transfer.ACL` (transfers); per-query is partial — see below | ⚠️ |
| Statistics + tracing | telemetry + Prometheus + dnstap + OTel | ✅ |
| DoT (RFC 7858) | `ExDns.Listener.DoT` | ✅ |
| DoH (RFC 8484) | `ExDns.Listener.DoH` | ✅ |
| DoQ (RFC 9250) | handler module; QUIC binding deferred | ⚠️ |

### Gaps that block migration

#### 🟥 Showstoppers — must fix before BIND-replacement claims

| Gap | Why it blocks | Effort |
|---|---|---|
| **Per-query view ACLs** (BIND `view` clauses) | Many BIND deployments serve different zone data to different clients (split horizon, internal vs external). We have transfer ACLs but not per-query view selection. Without this, a non-trivial fraction of BIND ops can't migrate. | Medium |
| **RFC 2845/8945 TSIG on inbound NOTIFY** | We accept NOTIFY but don't enforce TSIG verification on it. A BIND op who has secured their primary↔secondary topology with TSIG today loses that guarantee on migration. | Small (logic exists in `TSIG.Wire`; just needs a config gate on the NOTIFY handler) |
| **Dynamic DNS UPDATE (RFC 2136)** | Every Active Directory deployment uses RFC 2136 UPDATE for SRV record management. We have no UPDATE handler — request opcode 5 returns NOTIMP. Hard blocker for AD-integrated networks. | Medium-large |
| **Authoritative response signing for ANY** (RFC 8482 minimal-responses) | BIND defaults to refusing or minimising ANY queries. We currently respond with the full RRset list. Some ops view this as a DDoS amplification risk and require minimised ANY responses. | Small |
| **RPZ (Response Policy Zones)** | BIND's RPZ syntax + workflow is the de-facto standard for DNS-based blocklisting. Pi-hole-via-plugin (§3) covers the *behaviour*, but operators with existing RPZ zone files have no migration path. | Medium — write an RPZ-zone parser that compiles to plugin route entries |

#### 🟡 Important — most ops will need this within months

| Gap | Why it matters | Effort |
|---|---|---|
| **RFC 6975 algorithm signaling (DAU/DHU/N3U)** in OPT | Validating resolvers tell us which algorithms they support. We ignore it. Not blocking but considered baseline. | Small |
| **`rndc`-equivalent control channel** | Operators expect `rndc reload`, `rndc flush`, `rndc stats` as muscle memory. Our admin HTTP API covers the surface but the CLI shape is missing. Provide a `mix exdns.rndc` task or a `bin/exdnsctl` script. | Small |
| **`named.conf`-style include directive** | Big deployments split config into many files. Our `runtime.exs` model is fine but lacks an `include "/etc/exdns/zones.d/*.conf"` glob. | Small |
| **Per-zone NSEC vs NSEC3 selection** | Today the signer's NSEC3 chain is built but we don't publish it on every authoritative response yet. Need wiring + a per-zone config flag. | Medium |
| **Dynamic update via RFC 3007 (DDNS with TSIG)** | The TSIG-protected variant of RFC 2136. Same scope. | Same effort as RFC 2136 |
| **`forward only` per-zone** | BIND lets you say "forward `example.com` to `10.0.0.5:53`, recurse for everything else". We have global forwarder mode but no per-zone routing. | Small once §2 (policy phases) lands |
| **RFC 5155 opt-out for NSEC3** | Large delegation-heavy zones (TLDs) benefit hugely. Our NSEC3 chain ignores opt-out today. | Small |
| **RFC 8624 algorithm guidance enforcement** | Reject queries / refuse signing with deprecated algorithms (RSA/SHA-1, GOST). | Small |
| **TLSA + DANE serving** | We can serve TLSA records (already in our resource modules) but no integration tests, no UI surface, no signing helpers. | Small |
| **Glue auto-derivation** | Operators expect that adding NS records auto-derives required glue from existing A/AAAA. We require explicit glue today. | Small |

#### 🟦 Niche — defensible to skip for v1

| Gap | Why it's niche |
|---|---|
| **DNS64** (RFC 6147) — synthesise AAAA from A for IPv6-only clients | Mostly used by mobile carriers. Build only when a customer asks. |
| **Threat intelligence response policies** (BIND `dnsrps`) | Vendor-specific commercial workflows. The plugin framework (§3) is the better long-term answer. |
| **DLZ / SDB backends** | Loading zone data from SQL / LDAP. Replaceable by writing a `Storage` backend module. |
| **Statistics channel XML** (`/xml`) | We have Prometheus + dnstap + OTel. Modern monitoring doesn't need BIND's XML stats. |
| **`zone-statistics` per-zone counters** in BIND format | Telemetry tags every event with `zone`, so per-zone counters fall out of the Prometheus exporter. Format mismatch only. |
| **`auto-dnssec maintain`** | Equivalent to our `Rollover` module — same capability, different surface. |
| **`response-policy` with QNAME triggers** | Same observation as RPZ — `Plugin.Registry` covers the behaviour even if the BIND-syntax trigger language doesn't transfer 1:1. |

### Recommended migration roadmap

The five 🟥 items above are the gating set. Tackle in order:

1. **Per-query view ACLs** (largest BIND-deployment unlock).
2. **TSIG enforcement on inbound NOTIFY** (smallest, safest fix).
3. **Authoritative ANY minimisation** (RFC 8482 — small,
   ships in a single chunk).
4. **RPZ zone parser → plugin route entries** (gives existing
   BIND RPZ users a working migration without re-authoring
   their blocklists).
5. **RFC 2136 dynamic UPDATE handler** (largest single chunk;
   needed for AD environments).

After those land, ExDns can credibly position as a BIND
replacement for the 80% of deployments that don't depend on
the niche features above. The remaining 🟡 items can be
sequenced afterwards based on actual user demand surfacing
through GitHub issues.

### Comparison-test artefacts

The `test/conformance/` suite already cross-checks our
behaviour against the RFC clauses BIND implements. To go
further:

* Add `test/conformance/bind_dig_compatibility_test.exs`
  that, when BIND is installed, runs `dig` against ExDns and
  the same `dig` against a parallel BIND instance for a fixed
  set of queries. Diff the responses. Fail on any wire-level
  mismatch.
* Same shape for Knot DNS — `test/conformance/knot_compatibility_test.exs`.

Both tests are tagged `:integration` so CI runs without the
external servers don't need to install them.

---

## Sequencing across the six sections

Revised dependency graph (the API contract is now upstream of
both the UI and the plugin framework's UI surface):

```
              §1 phase 0 (formal API)
                       │
       ┌───────────────┼───────────────┐
       ▼               ▼               ▼
   §1 phase 1     §2 (policy       §3 (plugin
   (read-only UI)  phases)         framework)
       │               │               │
       │           ┌───┴────┐          │
       │           ▼        ▼          ▼
       │         §4 (anycast plugin) ──┘
       │
       ▼
   §1 phase 2-3 (mutations + DNSSEC UI)
       │
       ▼
   §5 (plugin tab API + UI rendering)
       │
       ▼
   §6 (BIND parity)
```

Build order:

1. **§1 phase 0 — formal API.** OpenAPI v1 spec +
   read-only routes + bearer-token issuer + SSE stream.
   `mix exdns.openapi.check` in CI. ~6 chunks.
2. **§2** — policy phase model + scratchpad + Registry. ~3 chunks.
3. **§3** — plugin behaviour, request/reply structs, Registry,
   PluginDispatch policy, libcluster integration. ~6 chunks.
4. **§1 phase 1 — read-only `ex_dns_ui`.** Separate Mix
   project. Generated typed API client. ZonesLive + ZoneLive
   in display-only mode + every-layout primitives + light/dark
   mode + SecondariesLive + observability dashboards. ~6 chunks.
5. **§4** — port `SourceIp` to `ex_dns_anycast` plugin.
   ~3 chunks. Validates §3 end-to-end.
6. **§1 phase 2-3** — mutating API routes + UI record edits
   + DNSSEC + secondaries UI. ~5 chunks.
7. **§5** — plugin OpenAPI fragment merging + plugin tab
   discovery + generic plugin views in the UI. ~4 chunks.
   Validates the plugin → API → UI contract via the anycast
   plugin's tab.
8. **§6** — BIND-gap fixes in the order recommended above.
   Each is a separate batch of chunks.

Total surface: ~35 implementation chunks across the six
sections, plus the BIND-gap items as ongoing follow-ups.
