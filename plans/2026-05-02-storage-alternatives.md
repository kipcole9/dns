# Cluster-resilient KV stores for ExDns (alternatives to Mnesia)

Date: 2026-05-02

Mnesia works (and Phase 4 ships with it) but has well-known weaknesses
under network partitions, and its API and operational model are
showing their age. Below is a survey of viable alternatives, scored
against ExDns's specific workload, with a recommendation.

## ExDns workload, for the record

* **Read-heavy.** Every DNS query is a read; reads must be local and
  fast (sub-millisecond).
* **Writes are rare and admin-driven.** Zone loads, NOTIFY-triggered
  refreshes. Tens to hundreds per day for most deployments.
* **Strong write consistency wanted.** Zone updates should be coherent
  cluster-wide; we don't want one node serving stale records while
  another serves new ones for any meaningful window.
* **Each node holds the full state.** No sharding — the data fits in
  RAM on every node, and we want every node to answer every query
  without a network hop.
* **Small clusters.** Typically 3–7 nodes per region.
* **CP > AP.** A short write outage during a partition is preferable
  to two zone variants leaking into the wild.

## Candidates

### 1. Mnesia (current default)

* OTP built-in.
* Distributed transactions, replicated `:ram_copies` everywhere.
* **Weak under netsplits**: no quorum mechanism, manual surgery
  required to reconcile after a split-brain. The ops community
  consensus is "Mnesia for non-critical state, look elsewhere if
  consistency matters."
* API has aged; documentation is thin; some operations (joining a
  schema across nodes, adding table copies) are easy to get wrong.
* **Verdict:** acceptable for our current scope but not the long-term
  pick.

### 2. Khepri (RabbitMQ team)

* https://github.com/rabbitmq/khepri
* Built by the RabbitMQ team **specifically as a Mnesia replacement**
  after they hit Mnesia's partition-tolerance limits in production.
* Tree-structured KV (paths like `/zones/example.com/www/a`).
* Backed by **Ra** (Raft) for consensus — strongly consistent writes,
  correct partition behavior, leader election baked in.
* BEAM-native, no external dependencies.
* Production-tested at RabbitMQ scale.
* Documented migration path from Mnesia.
* Active development as of 2026.
* Tree model is a natural fit for DNS hierarchy.
* **Verdict:** the right modern answer.

### 3. Ra (Raft library)

* https://github.com/rabbitmq/ra
* The Raft implementation underneath Khepri.
* Lower-level: you write the state machine yourself.
* Used directly by RabbitMQ for quorum queues.
* **Verdict:** more control than Khepri but more work; only worth it
  if Khepri's tree model proves wrong for ExDns. Unlikely.

### 4. DeltaCrdt

* https://github.com/derekkraan/delta_crdt_ex
* CRDT-based, AP system, eventual consistency.
* Used by Horde and Cachex's distributed mode.
* Excellent partition tolerance — every node accepts writes locally,
  diffs sync in the background.
* **Wrong consistency model for zone updates.** "Zone X has these
  records" is not naturally a CRDT — concurrent admin updates would
  merge in a way that's hard to reason about.
* **Verdict:** great for caches and presence; wrong for authoritative
  zone storage.

### 5. Riak Core / riak_core_lite

* https://github.com/riak-core-lite/riak_core_lite
* Consistent hashing, vnodes, ring management, hand-off.
* Battle-tested distributed-systems primitives.
* **Massive overkill** for our 3–7 node cluster with full
  replication. Would dominate the codebase.
* **Verdict:** appropriate when sharding is needed; we don't shard.

### 6. Partisan + custom store

* https://github.com/lasp-lang/partisan
* Alternative distribution layer for BEAM (replaces `:erl_distribution`).
* Solves BEAM dist's full-mesh and head-of-line-blocking issues.
* Doesn't provide a KV store on its own.
* **Verdict:** orthogonal — Partisan answers "how do nodes talk",
  not "where do I put state". If we hit BEAM-dist scaling pain,
  Partisan + Khepri is the natural pairing.

### 7. Single-node KV + manual replication (CubDB, RocksDB, Bitcask)

* CubDB: pure-Elixir embedded KV.
* RocksDB / Bitcask: NIF wrappers around C/Erlang KV engines.
* All single-node — you'd build replication on top yourself.
* **Verdict:** wrong layer; defeats the purpose of "cluster-resilient
  KV store".

## Recommendation: Khepri

Adopt **Khepri** as ExDns's clustered storage backend:

* Strong consistency under partitions (Raft).
* BEAM-native, no NIFs, no external services.
* Production-tested at RabbitMQ.
* Tree model maps cleanly onto DNS:
  `[<apex>, <reversed-labels>..., <type>]`.
* Designed by the RabbitMQ team to replace Mnesia, with Mnesia's
  weaknesses explicitly in mind.
* Modest learning curve (closer to Mnesia than to Riak Core).

Keep the existing pluggable `ExDns.Storage` behaviour. Add a
`ExDns.Storage.Khepri` backend alongside `ETS` and `Mnesia`. ETS
remains the single-node default; Khepri becomes the recommended
clustered backend; Mnesia stays as a fallback for users who prefer to
stick with OTP-built-in dependencies.

## What this would change

* New dep: `{:khepri, "~> 0.16"}` (or current latest).
* New module: `lib/ex_dns/storage/storage_khepri.ex` implementing
  the same `ExDns.Storage` callbacks.
* `ExDns.Cluster` learns to bootstrap a Khepri cluster on startup
  (Khepri has its own `add_member` story; replaces our manual Mnesia
  schema-join).
* Master election can be **dropped entirely** — Khepri's Raft leader
  IS the write coordinator. Our `ExDns.Cluster.commit/1` becomes a
  thin wrapper that just calls `:khepri.put` (Khepri internally
  routes the write to the leader; we don't need our own forwarding
  layer).
* The deferred P10f (multi-node Mnesia bootstrap) becomes moot.

## Migration order, if you want to do it

1. Add `ExDns.Storage.Khepri` alongside the existing backends; tests
   for it mirror the Mnesia-backend tests.
2. Add an integration test that spins up 3 BEAM peers using Khepri
   instead of `:global` for election; the cluster_test scenario
   should still pass.
3. Document Khepri as the recommended clustered backend in the README.
4. Leave Mnesia in place for one release cycle, then deprecate.
