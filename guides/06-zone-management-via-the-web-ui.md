# 06 — Zone management via the Web UI

The `dns_ui` Phoenix LiveView app is a thin operator surface over the same `/api/v1/*` endpoints documented in [05 — Zone management via curl](05-zone-management-via-curl.md). Anything you can do here you can do from the command line, and vice versa.

This guide assumes you've completed [01 — Installation, configuration & basic operations](01-installation-and-basic-operations.md) and have the UI running at <http://localhost:4000>.

## Sign in

Open the UI, enter the email + password you set up with `mix dns_ui.user.create`, and click sign in.

The UI doesn't do its own authentication against the server — instead, every UI user is **mapped to an ExDns API bearer token**. When you sign in, the UI stashes that token in a per-LiveView-process slot and uses it on every API call you make through the session. If your token's role is `viewer`, every "Save" button in the UI will fail with `403 Forbidden`. If it's `zone_admin` scoped to a glob, you'll only be able to mutate zones matching the glob.

> **Tip.** Run a `tail -f` on the server log in another window. Every API call the UI makes will appear; useful for understanding what a UI action actually does.

## The Zones list

Landing page after sign-in. One row per loaded zone, with:

* **Apex** — the zone name. Click to drill in.
* **Records** — total record count.
* **SOA serial** — bumps every time you change anything.
* **Status** — `loaded` (live), `stale` (loaded but underlying file modified), `error` (last reload failed; old zone still serving).
* **Reload** — re-reads the on-disk zone file. Same as `POST /api/v1/zones/<apex>/reload`.

Filter by name with the search box. Sort by clicking the column headers.

### Adding a new zone

The Web UI doesn't currently include an "add zone from scratch" wizard — zones come from on-disk files referenced by the `:ex_dns, :zones` config. To add one:

1. Create the zone file on the server host (`/etc/exdns/zones.d/newzone.com.zone`).
2. The autoload glob picks it up on next server restart, OR
3. SSH to the server and `bin/exdnsctl zone reload-all` to pick up new files without restart.

A future release may add a "create zone" UI flow; for now, files-on-disk are the source of truth for zone existence (records inside an existing zone can be edited freely from the UI).

## Zone detail

Click a zone row to see its records.

### Records table

Columns: **name**, **type**, **TTL**, **class**, **data**. The data column renders type-specific (a single IP for A / AAAA, "priority + target" for MX, the full CAA tag/value pair, etc.).

Filter by type with the dropdown. Filter by name with the text input — substring match against the FQDN.

### Inline edit

Click any cell value to edit in place. Press Enter to save (calls `PATCH /api/v1/zones/<apex>/records/<id>`), Escape to cancel. The SOA serial bumps automatically.

The TTL field accepts plain integers (seconds) or human-readable suffixes (`5m`, `2h`, `1d`).

### Add a record

The **Add record** button at the top opens a side panel:

1. Pick a type from the dropdown. The form re-renders to show the right fields:
   * `A` / `AAAA` — single IP.
   * `CNAME` / `NS` / `PTR` — single target name.
   * `MX` — priority + target.
   * `SRV` — priority + weight + port + target.
   * `TXT` — multi-line text (split into 255-byte chunks automatically per RFC 1035).
   * `CAA` — flags + tag + value.
   * `TLSA` — usage + selector + matching type + cert assoc data (hex).
   * `SOA` — locked; you can only edit the existing SOA, not add a new one.
2. Fill in the **name**. Unqualified (`api`) is treated as relative to the zone apex; fully qualified (`api.example.com.`) is taken literally.
3. Set **TTL**.
4. Save. The record is added via `POST /api/v1/zones/<apex>/records`, the SOA bumps, the row appears in the table.

### Delete a record

Hover a row → the trash icon appears at the right → click → confirm. Calls `DELETE /api/v1/zones/<apex>/records/<id>`.

### Live updates

The zone detail page subscribes to the SSE event stream (`/api/v1/events`). Edits made from another browser, from `curl`, from `nsupdate`, or from a peer node in a cluster appear in your records table within ~250 ms. No need to refresh.

### Journal timeline

The **Journal** tab shows the IXFR journal — every SOA bump with the diff between the previous and the current zone. Useful for "who changed what when" forensics; the entry includes the timestamp, the SOA serial change, and the records added / deleted.

## Secondaries

The **Secondaries** tab in the top nav lists zones this server pulls from a primary via AXFR / IXFR.

Per-row state machine snapshot:

| State | Meaning |
|---|---|
| `pending` | Initial — waiting for the first refresh. |
| `loaded` | Have a copy, serving normally. |
| `refreshing` | AXFR / IXFR in progress. |
| `expired` | Past the SOA expire — no longer serving (RFC 1035 requires refusing to serve). |
| `error` | Transfer failed; will retry per SOA retry. |

The **Refresh** button on a row triggers an immediate transfer (`POST /api/v1/secondaries/<apex>/refresh`). Useful when you've changed the primary and don't want to wait for the next NOTIFY.

Setup of the primary→secondary relationship is configuration, not UI — see [08 — Secondary zones, AXFR / IXFR / NOTIFY](08-secondary-zones-axfr-ixfr-notify.md).

## DNSSEC keys

The **Keys** tab shows every DNSSEC key in the store, grouped by zone:

* **Zone** — apex.
* **Key tag** — RFC 4034 key tag, the four-digit number that ties DNSKEY to RRSIG to DS.
* **Role** — KSK / ZSK.
* **Algorithm** — ECDSAP256SHA256 / Ed25519 / etc.
* **State** — `incoming` (published, not signing) / `active` (signing) / `retired` (not signing, still published).

### Rollover wizard

Click **Roll over** on a key:

1. **Prepare** — generates a new key in `incoming` state. Operators wait one TTL for resolvers to cache the new DNSKEY RRset.
2. **Active** — flips the new key to `active`, the old key stays active (overlap period). New signatures use the new key.
3. **Retire** — flips the old key to `retired`. Cached signatures still validate against the published DNSKEY; new ones use the new key.
4. **Purge** — removes the retired key from the published DNSKEY RRset. Operators wait one max TTL before doing this so cached signatures expire first.

Each phase calls `POST /api/v1/keys/<zone>/rollover/<phase>`. The wizard enforces phase ordering — you can't skip from `prepare` straight to `purge`.

## Plugins

The **Plugins** tab lists every registered plugin with its slug, version, health, and the routes it claims:

* `slug` — internal identifier.
* `module` — the Elixir module implementing the plugin.
* `node` — which cluster node owns it (relevant in cluster mode).
* `healthy?` — last health-check result.
* `routes` — CIDR + qname-suffix + qtype filters this plugin wants to be consulted for.

Click a plugin to open its tab. Each plugin can ship a custom UI; otherwise a generic tab renders the plugin's resources as tables / KV blocks / JSON trees.

### Black Hole dashboard

The bundled BlackHole plugin ships a custom dashboard:

* **Top tiles** — total queries, blocked count, allow ratio, top blocked domain.
* **Live query feed** — polling stream of `query.logged` events, with allow / block badges.
* **Blocklists** — subscribed remote adlists (Steven Black, AdGuard, custom URLs). Toggle, refresh, remove.
* **Allowlist / Denylist** — explicit per-domain entries that override blocklist matches.
* **Groups** — CIDR ranges of clients this filter applies to. Without a group entry covering a client, BlackHole passes the query through unchanged.

See [09 — BlackHole filtering](09-blackhole-filtering.md) for the full setup workflow.

## Theme + layout

* **Light / dark / system** toggle at the top right. The choice is stored in `localStorage`.
* The layout is built on **Every Layout** primitives (Box / Stack / Cluster / Sidebar / Switcher) — components never set their own external margin, so spacing is consistent across pages.

## Troubleshooting

* **"Failed to fetch" banners** → the UI can't reach the API. Check the server is up, `EXDNS_API_URL` matches the actual API bind, and the bearer token is still valid.
* **403 on every save** → your token is `viewer`-role or scoped to other zones. Re-issue with `mix exdns.token.issue --role zone_admin --scopes "*"` and re-create the UI user.
* **Zones list is empty but you know zones are loaded** → check the server log for zone validation errors; failed reloads keep the previous zone (which may not exist on a fresh boot).
* **Live updates stopped flowing** → the SSE connection dropped (proxies sometimes idle them out). Refresh the page; the LiveView reconnects.

## Related guides

* [01 — Installation, configuration & basic operations](01-installation-and-basic-operations.md)
* [05 — Zone management via curl](05-zone-management-via-curl.md) — the same operations, scriptable.
* [09 — BlackHole filtering](09-blackhole-filtering.md) — the BlackHole dashboard in depth.
