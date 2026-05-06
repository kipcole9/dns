# 02 — Extending to a clustered environment

This guide takes a working single-node ExDns server (built per [guide 01](01-installation-and-basic-operations.md)) and extends it into a multi-node cluster — without rewriting any zone files, re-issuing any tokens, or migrating any state.

## What "clustered" buys you

* **Identical answers everywhere.** Every node serves the same zone set, the same DNSSEC keys, the same TSIG keys, the same plugin registry, the same BlackHole blocklists.
* **Survives a node loss.** Lose any single member and the rest keep serving.
* **Operate from anywhere.** A `POST /api/v1/zones/.../records` against any node is replicated to the rest. No "primary" admin node.
* **Same code path as single-node.** No special clustering build, no separate adapter, no schema migration.

The substrate is `ExDns.EKV` — a single embedded KV store shared by every persistent subsystem. EKV runs in `cluster_size: 1` for the single-node story; raise the cluster size, point each member at its peers, and the same key-value primitives become a Raft-coordinated replicated log.

## Mental model

ExDns persists the following kinds of state, all in EKV under namespaced key prefixes:

| Subsystem | EKV prefix | What replicates |
|---|---|---|
| Zones | `zone/<apex>/records` | Full record set per loaded zone. |
| Plugin registry | `plugin/registry`, `plugin/route_index` | Registered plugins + dispatch table. |
| TSIG keyring | `tsig/keys` | Runtime-installed shared secrets. |
| DNSSEC key store | `dnssec/<zone>` | Per-zone signing keys with rollover state. |
| BlackHole | `blackhole/...` | Blocklists, allow / deny lists, groups, query log. |

Reads are local (ETS hot-path or eventually-consistent EKV `lookup`). Writes go through EKV's CAS path so the cluster picks one winner on any conflict. The query hot path never blocks on the cluster.

## Sizing — odd numbers, please

EKV is Raft-style: one node is leader, the rest follow, a majority must be reachable to commit a write.

| Cluster size | Survives losing | Notes |
|---|---|---|
| 1 | nothing | Single-node — same as guide 01. |
| 3 | 1 node | The smallest useful HA cluster. |
| 5 | 2 nodes | Higher write availability; modestly higher write latency. |
| ≥7 | 3+ | Diminishing returns; consider geo-sharding instead. |

**Don't run an even cluster size.** Two nodes survive zero failures (lose one and you've lost quorum) and add latency over single-node for nothing.

## Build a 3-node cluster on one machine (for development)

This is the fastest way to see the cluster behaviour without provisioning hosts.

Create three sibling release-style runtime configs. Each picks a different listener port and EKV data directory:

```elixir
# config/runtime-node1.exs
import Config

config :ex_dns,
  listener_port: 5301

config :ex_dns, :api,
  enabled: true,
  port: 9701,
  bind: {127, 0, 0, 1}

config :ex_dns, :ekv,
  enabled: true,
  data_dir: "/tmp/exdns-node1",
  cluster_size: 3,
  mode: :member,
  peers: [
    %{name: :ex_dns, host: "127.0.0.1", port: 9301},
    %{name: :ex_dns, host: "127.0.0.1", port: 9302},
    %{name: :ex_dns, host: "127.0.0.1", port: 9303}
  ],
  bind_port: 9301
```

Repeat with `node2` (listener `5302`, API `9702`, data dir `/tmp/exdns-node2`, bind `9302`) and `node3` (`5303`, `9703`, `/tmp/exdns-node3`, `9303`). The `peers` list is identical on all three.

Start each in its own terminal:

```bash
ELIXIR_ERL_OPTIONS="-name node1@127.0.0.1" \
  EXDNS_RUNTIME_CONFIG=config/runtime-node1.exs \
  mix run --no-halt

ELIXIR_ERL_OPTIONS="-name node2@127.0.0.1" \
  EXDNS_RUNTIME_CONFIG=config/runtime-node2.exs \
  mix run --no-halt

ELIXIR_ERL_OPTIONS="-name node3@127.0.0.1" \
  EXDNS_RUNTIME_CONFIG=config/runtime-node3.exs \
  mix run --no-halt
```

Each member logs `[EKV ex_dns] startup quorum reached after Nms` once it sees the rest. Until quorum is reached, the API is up but read-only — writes block.

## Verify replication

Write a record against node 1's API:

```bash
TOKEN='<your zone_admin token>'

curl -sS -X POST http://127.0.0.1:9701/api/v1/zones/example.test/records \
  -H "authorization: Bearer ${TOKEN}" \
  -H "content-type: application/json" \
  -d '{"name":"replicated","type":"A","ttl":60,"data":"203.0.113.7"}'
```

Within a few hundred milliseconds, query node 2 and node 3:

```bash
dig @127.0.0.1 -p 5302 replicated.example.test A +short
dig @127.0.0.1 -p 5303 replicated.example.test A +short
```

Both should return `203.0.113.7`. Same outcome for TSIG `put`, plugin registration, BlackHole list updates, DNSSEC key installation.

## Production: three real hosts

Replace the loopback addresses with the hosts' real IPs. EKV speaks its own peer protocol over TCP — pick a port (default convention is one above the API port) and open it in the firewall between cluster members only:

```elixir
# config/runtime.exs on every node
config :ex_dns, :ekv,
  enabled: true,
  data_dir: "/var/lib/exdns/ekv",
  cluster_size: 3,
  mode: :member,
  bind_port: 9300,
  peers: [
    %{name: :ex_dns, host: "ns1.internal", port: 9300},
    %{name: :ex_dns, host: "ns2.internal", port: 9300},
    %{name: :ex_dns, host: "ns3.internal", port: 9300}
  ]
```

Each node also runs a DNS listener on port 53. Front them with whatever load-balancing your environment provides — anycast IP from a router, ECS-aware GSLB, or a simple round-robin DNS NS-record set.

## Adding a member to an existing cluster

EKV supports raising `cluster_size` while running, but the safe operation order matters:

1. Bring the new node online with `cluster_size: <new size>` and the full peer list (including itself).
2. Update the existing nodes' `peers` list to include the new member.
3. Restart the existing nodes one at a time. Wait for `startup quorum reached` between restarts.
4. Verify on every member: `bin/exdnsctl cluster status`.

Going from 3 → 5 doubles tolerated losses without a write-throughput cliff. Going from 1 → 3 is a one-time operation and the most disruptive — schedule it during a maintenance window.

## Read-only observers

A node that wants the data but is too slow / too far / too cheap to participate in quorum can run as an observer:

```elixir
config :ex_dns, :ekv,
  mode: :observer,
  peers: [...]      # same peer list as the voters
```

Observers replicate every write but don't vote. Useful for DR sites, query-only edge nodes, or "I want a read replica in another region without inflating my write latency."

## What clustering does *not* give you

* **Cross-region low-latency answers.** EKV replicates writes synchronously to the majority — if your nodes are 100 ms apart, every write is at least 100 ms. Reads are local and fast. For per-region answer fan-out, layer the **Anycast plugin** on top of a single replicated dataset.
* **Hot reload across the cluster.** A `POST /reload` reloads on the targeted node only. To reload on every node, hit each node's API in turn or use `bin/exdnsctl zone reload-all`.
* **Magic conflict resolution.** Concurrent UPDATEs to the same RRset go through CAS and one wins; the other gets `{:error, :conflict}`. Your client decides whether to retry.

## Operating the cluster

* **Watch quorum**: every node exposes `/api/v1/health` and `/api/v1/ready`. `ready` flips to false when the node loses quorum.
* **Stop one at a time**: `bin/exdnsctl drain && systemctl stop exdns`. The drain blocks until in-flight queries complete, then the BEAM exits cleanly.
* **Backup is just the EKV data directory.** It's a small set of SQLite files. `tar -czf` it; restore by stopping the node, replacing the directory, restarting.

## Where to go next

* **Different roles for different nodes** — pure-authoritative public NS plus a recursive resolver pool for the LAN: see [03 — Server modes](03-server-modes-authoritative-recursive-stub.md).
* **DNSSEC across the cluster** — keys live in EKV so signing works on any node: [07 — DNSSEC signing & rollover](07-dnssec-signing-and-rollover.md).
* **Observability** — Prometheus exporter, structured logs, OpenTelemetry tracing: [10 — Monitoring & observability](10-monitoring-and-observability.md).
