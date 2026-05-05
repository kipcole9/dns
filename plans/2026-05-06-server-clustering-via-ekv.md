# Server-wide clustering via EKV — plan

**Date:** 2026-05-06
**Status:** Plan only — no implementation work yet.
**Touches:** `ExDns.Storage` (zones), `ExDns.DNSSEC.KeyStore`, `ExDns.TSIG.Keyring`, `ExDns.Plugin.Registry`, `ExDns.BlackHole.Storage`, `ExDns.Zone.Catalog.Subscription` (leader election), and a small new dependency on `:ekv`.

## Goal

Make ExDns operate as a true multi-node cluster — zone changes, DNSSEC key state, TSIG keyring entries, plugin registrations, and BlackHole configuration all converge across every node — without changing the resolver's hot path or breaking the single-node deployment story. The clustering substrate should be a single, well-understood library, swap-able per subsystem if needed.

The proposal: **adopt EKV (`chrismccord/ekv`) as the cluster KV for the subsystems above**, leaving each subsystem's existing behaviour in place so adapters slot in without touching plugin code, the resolver, or the API layer.

## Context — what's already pluggable

This work is much smaller than it sounds because every subsystem listed above already has a behaviour shielding it from the persistence choice:

* `ExDns.Storage` (zones) — `ExDns.Storage.ETS` is the current adapter.
* `ExDns.BlackHole.Storage` — `Storage.SQLite` is the current adapter.
* `ExDns.Plugin.Registry.Backend` — `Backend.PersistentTerm` is the current adapter (introduced in this session as part of the prep work).
* `ExDns.DNSSEC.KeyStore` and `ExDns.TSIG.Keyring` are not yet behaviours, but their public surface is small enough to retrofit one.

Adopting a clustered KV is therefore a **per-subsystem adapter swap**, not a rewrite. The job is: add the dep, write one EKV adapter per subsystem, ship them as opt-in backends.

## Why EKV, not Khepri or DurableServer

| Property | EKV | Khepri | DurableServer |
|---|---|---|---|
| What it is | Embedded sharded-SQLite KV with opt-in linearizable CAS via Raft-style quorum | Tree-structured Raft-replicated DB (Mnesia replacement, RabbitMQ team) | GenServer-shaped behaviour for durable processes; *uses* a KV underneath |
| Single-node = cluster mode | Yes (one-member cluster) | Yes (one-node Raft) | Yes (no cluster needed) |
| Production track record | Young (v0.2.x) | RabbitMQ uses it as the Mnesia replacement | Very young (v0.1.1) |
| External infra | None | None | None hard-coded; Tigris commonly paired |
| Fit for our problem | Direct (it's a KV) | Direct (it's a KV) | Wrong shape (it's not a KV) |
| Operational simplicity | High (SQLite under the hood, no separate daemon) | Medium (Ra log files + snapshots) | N/A |

**EKV wins for our use case** on three points:

1. **Same code path single-node and clustered.** Operators who run a one-box ExDns get the same library, and the day they add a second node they call `Node.connect/1` + raise `:cluster_size`. No migration, no schema change. Khepri also supports both modes, but the operational mental model is heavier (you're running Raft).

2. **SQLite under the hood is a known quantity.** The vendored `exqlite` NIF is the same C shape every Elixir+SQLite codebase already vets. Khepri's Ra logs are equally fine but operators who want to inspect state outside the BEAM have a harder time.

3. **API surface is small.** EKV is `get/put/delete/cas/scan/subscribe`. That's 95% of what every subsystem here needs. Khepri's tree + transactions + projections + watchers is more powerful than we need; we'd be using a small subset of a large surface.

**Khepri remains the right answer** if (a) we hit a real EKV bug we can't get fixed quickly, or (b) we need transactional cross-key updates beyond what CAS gives us. We're not at either today.

**DurableServer** is the wrong tool for the registry / KV problem. It's `GenServer with persistent state + cluster-aware placement`. We'd be wrapping a GenServer around a static-ish list of plugins to get something a KV provides natively. Skip.

## What gets clustered (and what doesn't)

| Subsystem | Cluster need | Adapter? | Notes |
|---|---|---|---|
| Zone storage | **Strong** | Yes | Updating a zone on one node should propagate. Today operators edit the file on every node OR use the secondary mechanism for replication. |
| DNSSEC key state | **Strong** | Yes | A KSK rolling over on one node while another node still publishes the old one is a real bug class. |
| TSIG keyring | **Strong** | Yes | Adding a TSIG key on one node should propagate without a restart. |
| BlackHole configuration (lists, allow / deny, groups) | **Medium** | Yes | Operator-curated; should propagate. |
| Plugin registry | **Medium** | Yes | Same plugins on every node is the typical case. |
| Catalog subscription leader | **Medium** | No (different shape) | Pattern is `:global` leader election + the existing GenServer; not a KV problem. |
| BlackHole query log | **None** | No | Per-node by design (per-node clients, per-node visibility). |
| RRL state | **None** | No | Rate limiting is correctly per-node — each node sees its own client traffic. |
| IXFR journal | **None** | No | Per-zone history; nodes catch each other up via AXFR. |
| Zone snapshot | **None** | No | Per-node persistence; redundant with clustered storage. |
| Recursor cache | **None** | No | Per-node by design. |

The "None" rows are why **adopting EKV doesn't mean adopting it for the whole codebase** — only for the five subsystems above.

## Architecture per subsystem

### Zone storage (`ExDns.Storage`)

Add `ExDns.Storage.EKV` adapter. Schema:

```
plugins:zone:{apex}                → %{records: […], serial, source, kind}
plugins:zone:{apex}:soa            → cached SOA for fast serial reads
```

Reads on the resolver hot path: today they hit ETS. Under EKV, they'd hit the local SQLite shard (microseconds, no network). Writes (zone reload, RFC 2136 UPDATE, secondary AXFR-apply) write through EKV's CAS so all nodes converge.

Critical: the resolver pipeline reads zones tens of thousands of times per second. The adapter MUST cache locally — EKV's per-node SQLite shard is essentially that cache, but we should still measure end-to-end query latency before declaring victory.

### DNSSEC key state (`ExDns.DNSSEC.KeyStore`)

Add a behaviour wrapper around the existing module + an EKV adapter. Keys:

```
dnssec:zone:{apex}:keys            → [%{role, algorithm, key_tag, state, …}]
dnssec:zone:{apex}:rollover        → current rollover phase + scheduled times
```

CAS on the key list is the safety property — two nodes must not both decide to advance a rollover phase simultaneously.

### TSIG keyring (`ExDns.TSIG.Keyring`)

Add a behaviour + EKV adapter. Keys:

```
tsig:keys                          → %{key_name => %{algorithm, secret}}
```

Small, low-frequency mutation; reads on every signed message. Local SQLite shard makes the read free.

### BlackHole configuration

`ExDns.BlackHole.Storage` already has the right shape. Add `Storage.EKV`. Keep `Storage.SQLite` as the per-node default for operators who don't need clustering.

Subdivide what's clustered:

* Lists, allow / deny, groups → cluster
* Query log → stays per-node (already documented)
* Compiled match set → stays per-node (always derived from the clustered config)

### Plugin registry

`Plugin.Registry.Backend` already exists. Add `Backend.EKV`. Keys:

```
plugins:registry                   → %{slug => entry}
plugins:routes                     → flat route index
```

Note: the route index is the high-throughput read path. The EKV adapter caches it locally in `:persistent_term` (same as today) and updates the cache on subscribe-notifications from EKV.

## Sequencing

Each chunk lands independently, with the in-process default still working until the EKV adapter is wired.

1. **Behaviour extraction for KeyStore + Keyring** (~2 chunks). They don't have behaviours today; retrofit before adding a second backend.

2. **Add `:ekv` dep + helper module** (~1 chunk). One umbrella module (`ExDns.EKV`) starts the embedded KV at boot, exposes `get/put/cas/subscribe/scan` wrappers used by every adapter.

3. **Per-subsystem EKV adapter, one at a time** (~1–2 chunks each):
   * Plugin registry — smallest, validates the pattern.
   * TSIG keyring — small, security-critical, good second pass.
   * BlackHole configuration — adapter already-shaped.
   * DNSSEC key state — needs CAS on rollover phase advance.
   * Zone storage — biggest; benchmark the hot path before declaring done.

4. **Cluster-membership story** (~2 chunks). libcluster topology config + EKV's `:cluster_size` setting + a small `mix exdns.cluster.status` task showing each node's role in the cluster.

5. **Operational docs** (~1 chunk). README section on switching from per-node to clustered, including the safety rules (don't downsize below quorum, etc).

Total: ~12 chunks. Materially smaller than a from-scratch clustering effort because the behaviours are already in place.

## Risks

* **EKV is v0.2.** A single library version pinned across five subsystems is an asset concentration. Mitigation: every subsystem keeps its existing single-node default; if EKV needs to be replaced, the unit of work is one adapter per subsystem, not a rewrite.

* **Hot-path read latency.** Zone storage reads happen on every query. EKV's local SQLite shard is the cache; we still need to measure that the local read is `≤ 5 µs` median. Benchmark before merging the zone-storage adapter.

* **CAS conflicts on key rollover.** If two nodes try to advance a rollover phase at the same instant, one wins via CAS, the other re-reads + re-decides. The semantics need explicit testing — the `Rollover.advance/2` function MUST be idempotent + retry-safe.

* **Partition behaviour.** EKV's CAS requires quorum. A two-node cluster that splits has *no* writable side. Operators picking cluster sizes need to know this; `mix exdns.cluster.status` should make it visible.

* **Operator confusion: "is my cluster broken?"** When the same DNS server runs both single-node and clustered modes via the same library, operators may not realise they need to set `:cluster_size`. Default to `1` (single-node, no quorum needed) so the no-config case Just Works.

## Non-goals

* Adopting EKV for the recursor cache, RRL, IXFR journal, or query log — those are correctly per-node.

* Replacing SQLite as BlackHole's *single-node* default. SQLite stays; the EKV adapter is opt-in for operators who want clustered BlackHole config.

* Rewriting the catalog-subscription leader-election story. The existing `:global` registration is fine; that's a different problem from a KV.

* Migration tooling from existing DETS / SQLite stores into EKV. The migration story is "stop the cluster, copy state via a one-shot Mix task, start the cluster". Operator-managed; tooling beyond a single Mix task isn't in scope.

## What this plan does NOT commit to

A timeline. Every chunk above is well-scoped, but nothing here triggers without a real multi-node deployment driving the requirement. Until then the per-subsystem behaviours remain in place with their single-node defaults, and any session opening with "let's stand up clustering" can pick up at chunk 1 of the sequencing list above.
