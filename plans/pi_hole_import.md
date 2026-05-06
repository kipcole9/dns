# Pi-hole import

Post-launch follow-on for `exdns import pi-hole <path>`.
The CLI surface is reserved (T3.4); the implementation
landing here is the actual mapping work.

## Goal

A migration path that takes a pi-hole admin's box and
recreates the equivalent ExDns BlackHole configuration
in a single command:

```bash
sudo exdns import pi-hole /etc/pihole
```

Reads pi-hole's state, creates the same blocklists +
allow/deny + groups in ExDns, refreshes once, prints a
summary.

## Why this matters

Pi-hole is the dominant home-DNS-with-ad-blocking
product and migrating off it is currently a manual
re-do. Operators typing 30 commands to re-create their
config is the reason most don't switch. A working
import is the most direct way to grow the user base
that's currently on pi-hole.

## What pi-hole stores

| File | Purpose |
|---|---|
| `/etc/pihole/gravity.db` | SQLite — adlists, regex blacklist, exact white/black lists, groups, group memberships. |
| `/etc/pihole/setupVars.conf` | Plain key=value — chosen blocking mode (NXDOMAIN / NODATA / IP), upstream resolvers, network interface, query log retention. |
| `/etc/pihole/dhcpcd.conf` | Optional DHCP server config — out of scope. |
| `/etc/pihole/local.list` | Local A records — could be imported as a small zone. |
| `/etc/pihole/dns-servers.conf` | Curated upstream choices — informational only. |

Schema reference for `gravity.db` — pi-hole publishes it
in their repo under `advanced/Templates/gravity.db.sql`.
The relevant tables:

* `adlist` — id, address (URL), enabled, comment, date_added.
* `domainlist` — id, type (0 = exact-block, 1 = exact-allow, 2 = regex-block, 3 = regex-allow), domain, enabled, comment.
* `group` — id, name, enabled, description.
* `adlist_by_group` / `domainlist_by_group` — many-to-many membership.
* `client` / `client_by_group` — per-client overrides (we map these to BlackHole groups by CIDR).

## Mapping

| pi-hole entity | ExDns equivalent |
|---|---|
| `adlist` row (URL + enabled) | `Storage.put_blocklist(%{"id" => "imported-#{address-hash}", "url" => address, "name" => comment, "enabled" => enabled})` |
| `domainlist` type=0 (exact black) | `Storage.put_deny(%{"domain" => domain, "comment" => comment})` |
| `domainlist` type=1 (exact white) | `Storage.put_allow(%{"domain" => domain, "comment" => comment})` |
| `domainlist` type=2/3 (regex) | Same modules' regex variant — needs a `Storage.put_deny_regex` we don't yet have. **Schema gap.** |
| `group` + `adlist_by_group` + `client_by_group` | `Storage.put_group(%{"id" => "imported-#{name}", "name" => name, "cidrs" => cidrs_from_clients, "blocklist_ids" => mapped_adlist_ids, "enabled" => enabled})` |
| `setupVars.conf BLOCKING_MODE` | `:ex_dns, :black_hole, :default_block_response` |
| `setupVars.conf PIHOLE_DNS_*` | `:ex_dns, :forwarder, :upstreams` (only if `recursion: false`) |
| `setupVars.conf PIHOLE_INTERFACE` | Detect, log, but don't auto-set — we don't bind to an interface, we bind to an address. |

## Open questions

* **Regex blacklist** — pi-hole supports regex matches; ExDns BlackHole.Set is exact-match + wildcard only. Either extend BlackHole to support regex (small lib change) or skip regex entries with a warning.
* **Per-client overrides** — pi-hole has fine-grained per-MAC-address overrides via the `client` table. We translate to CIDR-only groups; per-MAC needs a DHCP integration we don't have. Document the gap.
* **Query log retention** — pi-hole's `MAXDBDAYS` maps to our `:query_log_max_age_seconds`; trivial.
* **Adlist refresh schedule** — pi-hole defaults weekly; we default to `:default_subscriber_interval_seconds`. Trivial map.
* **DNSSEC** — pi-hole's DNSSEC validation is unrelated to BlackHole and applies to FTL's recursor; not relevant to our import.

## Implementation plan

1. **Reader module** `ExDns.PiHole.Importer`:
   * `read_setup_vars/1` — parse `setupVars.conf` into a map.
   * `read_gravity_db/1` — read the SQLite via `:exqlite`, return a struct: `%{adlists: [...], denylist: [...], allowlist: [...], groups: [...]}`.
   * `apply!/1` — call into `BlackHole.Storage` to upsert each row.

2. **CLI subcommand** `import_pi_hole(path)`:
   * Validate the path exists + has the expected files.
   * Dry-run mode (`--dry-run`) prints what would be done.
   * Real run: apply, then refresh all imported blocklists, print summary.

3. **Tests**:
   * Fixture: a minimal `gravity.db` checked into `test/fixtures/pi-hole/`.
   * Verify each entity type round-trips.
   * Verify dry-run doesn't mutate state.

## Effort estimate

About 2 days. The mapping is straightforward; the long
pole is the regex-blacklist question (do we extend
BlackHole or document the gap).

## When to do it

After the elixir-dns-test.com deployment is live and
soaking. The import target audience is "people running
pi-hole today who saw a tweet" — that audience doesn't
exist until ExDns is launched.
