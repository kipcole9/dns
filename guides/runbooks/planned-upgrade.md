# Runbook — planned upgrade

How to roll a new release of ExDns through a multi-node cluster with zero query downtime.

## Pre-upgrade checklist

* Read the release's CHANGELOG. Note any **breaking changes** under that release's section. Note any **migration steps** the maintainer flagged.
* Verify backups are current (see [backup-and-restore.md](backup-and-restore.md)). The night before a planned upgrade is a fine time to make a fresh full backup.
* Run the new release through staging first. The same `runtime.exs`, the same zone files, the same EKV data dir copy if practical.
* Pick a low-traffic window. DNS query rates have very predictable shapes — your monitoring already knows when yours is lowest.
* Notify the on-call: rolling upgrade in progress, expected duration, comms channel.

## Single-node upgrade

```bash
# 1. Stage the new release.
scp ex_dns-0.2.0.tar.gz exdns@host:/tmp/

ssh host
sudo install -d -o root -g root -m 0755 /opt/exdns-0.2.0
sudo tar -xzf /tmp/ex_dns-0.2.0.tar.gz -C /opt/exdns-0.2.0
sudo chown -R root:root /opt/exdns-0.2.0

# 2. Atomically swap the symlink.
sudo ln -sfn /opt/exdns-0.2.0 /opt/exdns.new
sudo mv -T /opt/exdns.new /opt/exdns

# 3. Drain + restart.
sudo systemctl restart exdns

# 4. Verify.
sudo systemctl status exdns
journalctl -u exdns --since '1 minute ago' | grep -i error
dig @127.0.0.1 example.com SOA
```

`systemctl restart` triggers `ExDns.Drain` (SIGTERM → drain → exit), then starts the new release. Total interruption: ~5 seconds for a quiet server, ~30 seconds for a busy one with long-poll TCP connections.

If anything in step 4 looks wrong, roll back:

```bash
sudo ln -sfn /opt/exdns-0.1.0 /opt/exdns
sudo systemctl restart exdns
```

Keep the previous version installed for at least one full rollover cycle (e.g. one week). Disk is cheap; "we deleted last week's release" pain isn't.

## Cluster upgrade — rolling

Rule: **one node at a time**, each one fully drained + rejoined before touching the next.

```bash
NODES=(ns1 ns2 ns3)

for n in "${NODES[@]}"; do
  echo "=== Upgrading $n ==="

  # Stage the new release.
  scp ex_dns-0.2.0.tar.gz exdns@$n:/tmp/
  ssh $n "
    sudo install -d /opt/exdns-0.2.0 &&
    sudo tar -xzf /tmp/ex_dns-0.2.0.tar.gz -C /opt/exdns-0.2.0 &&
    sudo chown -R root:root /opt/exdns-0.2.0
  "

  # Drain + replace + restart.
  ssh $n sudo /opt/exdns/bin/exdnsctl drain
  ssh $n sudo systemctl stop exdns
  ssh $n sudo ln -sfn /opt/exdns-0.2.0 /opt/exdns
  ssh $n sudo systemctl start exdns

  # Wait for this node to rejoin quorum before moving on.
  until ssh $n curl -sS http://127.0.0.1:9572/readyz | grep -q '"status":"ready"'; do
    sleep 2
  done

  # Sanity-check before continuing.
  dig @$n example.com SOA +short
  echo "$n upgraded OK"
done
```

If a node fails to rejoin quorum, **stop the rollout**. Investigate before touching the next. Cluster integrity matters more than schedule.

## What can go wrong

### Schema migration required

Some releases ship a one-time data migration (e.g. EKV layout change). The CHANGELOG calls it out under a `### Migration` heading.

Pattern:

1. Take all nodes down. **Cluster-wide downtime — schedule accordingly.**
2. Run the migration once on one node: `sudo /opt/exdns/bin/ex_dns eval 'ExDns.Release.migrate_to_v0_2_0()'`
3. Bring the migrated node up. Verify.
4. On the other nodes, **wipe** EKV (`sudo rm -rf /var/lib/exdns/ekv`) and let them sync from the migrated node.

This is the only legitimate reason for a cluster-wide outage during an upgrade. The maintainer will flag it loudly.

### New defaults flip

Tier-1 hardening flipped RRL and DNS Cookies on by default. A future release might do the same for something else (e.g. enforce-cookies). If the new default conflicts with your environment:

1. Pin the old behaviour in `runtime.exs` BEFORE upgrading: `config :ex_dns, :cookies, enforce: false`.
2. Test the new release in staging WITH the old behaviour pinned.
3. Roll out.
4. Plan the change to the new default as a separate, deliberate operation.

### Rollback after partial cluster upgrade

If 2 of 3 nodes are on the new version and the new version turns out to misbehave:

1. Drain + stop the bad nodes, leaving the unchanged one running.
2. The single remaining node alone won't have quorum (`cluster_size: 3` requires 2 votes for CAS). Eventual reads still work. Most queries still answer correctly.
3. If you must restore quorum quickly, edit the unchanged node's `runtime.exs` to `cluster_size: 1` and restart it. **Cluster identity changes** — you'll need to reset and rejoin the others when they come back.
4. Bring the rolled-back nodes (old version) back online. Wait for quorum.
5. Investigate the failure offline.

### Erlang / Elixir version mismatch

A new release may bump the minimum Elixir / OTP. The release tarball ships its own ERTS, so the host's Elixir version doesn't matter — but the host's libc / openssl version does. Bookworm-compiled releases run on Bookworm and newer, not on Bullseye. If you upgrade ExDns and immediately the BEAM crashes with `ld-linux: GLIBC_X.YY not found`, you need to either rebuild against your host or upgrade the host first.

## Post-upgrade verification

```bash
# 1. Every node serves queries.
for n in ns1 ns2 ns3; do
  echo "$n:"
  dig @$n example.com SOA +short
done

# 2. EKV quorum is healthy.
sudo /opt/exdns/bin/exdnsctl cluster status

# 3. No new errors / warnings in the log.
journalctl -u exdns --since '10 minutes ago' | grep -iE 'error|warning'

# 4. Health probes pass on every node.
for n in ns1 ns2 ns3; do
  curl -sS http://$n:9572/readyz | jq
done

# 5. Watch query metrics for ~30 minutes. Look for:
#    - Spike in SERVFAIL? (DNSSEC validation regression?)
#    - Spike in REFUSED? (config interpreted differently?)
#    - Spike in latency? (resource regression?)
```

If everything's clean after 30 minutes, the upgrade is done. Document the window in the change log; close the ticket.

## Cadence

* **Patch releases** (0.2.0 → 0.2.1): roll within a week. Usually safety fixes.
* **Minor releases** (0.2.x → 0.3.0): roll within a month, after staging-bake.
* **Major releases** (0.x → 1.0): plan a maintenance window, expect schema migration, communicate.
