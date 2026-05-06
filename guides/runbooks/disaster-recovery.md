# Runbook — disaster recovery

This runbook covers the bad days. Read it cold once a year so the steps are familiar before an outage drills the muscle memory.

## Decision tree

```
Are queries failing?
├── No → Wrong runbook. See [planned upgrade] or [backup/restore].
└── Yes
    Are queries failing on EVERY node?
    ├── No → Single-node failure. Drain + replace.
    └── Yes
        Is your primary DNSKEY private key still readable?
        ├── Yes → Service-level outage. Restore from backup.
        └── No → KEY-LOSS DR. Read §"Lost all signing keys".
```

## §1 — Single-node failure (cluster intact)

Symptoms: one member's `journalctl -u exdns` is full of crashes, `/readyz` returns 503, EKV peer says "down".

Action:

```bash
# 1. Drain the bad node so it stops getting traffic.
sudo /opt/exdns/bin/exdnsctl drain

# 2. Stop and reinstall.
sudo systemctl stop exdns
sudo mv /var/lib/exdns/ekv /var/lib/exdns/ekv.broken-$(date +%s)

# 3. Bring back up — EKV will sync state from the surviving members.
sudo systemctl start exdns
journalctl -u exdns -f
# Wait for: "[EKV ex_dns] startup quorum reached after Nms"
```

If the host itself is dead, provision a replacement and follow the *Restore on a fresh host* section of [backup-and-restore.md](backup-and-restore.md).

## §2 — Cluster-wide failure (every node down)

Quorum is gone. Rare in practice; mostly happens when a regional outage takes out the data centre or a mass-deploy goes sideways.

Action:

```bash
# 1. Pick the node with the most recent successful EKV write.
#    If you have a leader-tracking dashboard, that node is
#    the one to bring up first.
ssh ns1
sudo /opt/exdns/bin/ex_dns eval 'ExDns.EKV.lookup("zone/example.com/records") |> Enum.count() |> IO.inspect()'

# 2. On that node only, override cluster_size to 1 in
#    runtime.exs to break the quorum requirement, restart,
#    and verify it's serving.
sudo $EDITOR /etc/exdns/runtime.exs
#   config :ex_dns, :ekv, cluster_size: 1
sudo systemctl restart exdns

dig @127.0.0.1 example.com SOA +short

# 3. Bring the other nodes back one at a time.
#    Restore their runtime.exs to the cluster setting and
#    start. They'll sync from the leader.
ssh ns2 sudo systemctl start exdns
ssh ns3 sudo systemctl start exdns

# 4. Once all members report quorum, bump cluster_size on
#    ns1 back to 3 and restart it.
ssh ns1
sudo $EDITOR /etc/exdns/runtime.exs   # cluster_size: 3
sudo systemctl restart exdns
```

## §3 — Restore from the most recent backup

When the EKV state on every node is corrupt or gone:

```bash
# 1. Stop the service on every node.
for n in ns1 ns2 ns3; do ssh $n sudo systemctl stop exdns; done

# 2. On ONE node (call it the "donor"), restore the backup.
#    See backup-and-restore.md §"Restore on the same host".

# 3. Start the donor.
ssh ns1 sudo systemctl start exdns

# 4. On the OTHER nodes, do NOT restore. Wipe the EKV dir
#    so they bootstrap a fresh sync from the donor.
ssh ns2 sudo rm -rf /var/lib/exdns/ekv
ssh ns2 sudo systemctl start exdns
ssh ns3 sudo rm -rf /var/lib/exdns/ekv
ssh ns3 sudo systemctl start exdns
```

You will lose every UPDATE / record edit / plugin change made between the backup timestamp and now. Communicate.

## §4 — Lost all signing keys for a zone

You don't have the DNSSEC private keys and don't have a backup that does. The signed zone is poison — every validating resolver on the internet will return SERVFAIL until the chain of trust is broken at the parent.

This is recoverable, but only if you act before the existing RRSIGs expire (see your zone's `signature_expiration` window). After expiry, every resolver SERVFAILs anyway.

```bash
# 1. At the registrar — REMOVE the DS records for the lost
#    zone. This unhooks the chain of trust at the parent.
#    Resolvers will treat the zone as insecure-on-purpose.
#    (Cloudflare: DNS → DNSSEC → Disable. Verisign sees
#    the change in tens of minutes.)

# 2. Wait one parent-zone TTL (.com is ~24h). During this
#    window, validating resolvers see "DS exists but DNSKEY
#    doesn't match" and SERVFAIL. There is no way to make
#    this faster.

# 3. Once the DS is out of caches, re-sign the zone with
#    fresh keys.
sudo /opt/exdns/bin/exdnsctl key generate \
  --zone example.com --role ksk --algorithm ecdsap256sha256 --state active
sudo /opt/exdns/bin/exdnsctl key generate \
  --zone example.com --role zsk --algorithm ecdsap256sha256 --state active

# 4. At the registrar — submit the new DS for the new KSK.
sudo /opt/exdns/bin/exdnsctl key dnskey-to-ds --zone example.com --role ksk
# Submit the printed DS at the registrar.

# 5. Wait one more parent-zone TTL for the new DS to
#    propagate.

# 6. Verify with DNSViz (https://dnsviz.net/) — green is good.
```

The unsigned-window outage in step 2 is the real DR cost. Have a comms plan ready (status page, customer notification) so the team isn't scrambling.

## §5 — Lost the bearer-token registry

Hashed at rest, so the file leaking doesn't grant access — but the operator who lost it can't authenticate either.

```bash
# 1. Generate a fresh registry by issuing a new
#    cluster_admin token.
sudo /opt/exdns/bin/exdnsctl token issue \
  --role cluster_admin --label recovery
# Note the printed secret.

# 2. Use that token to revoke every other token via the
#    API, then re-issue per-operator tokens.
TOKEN='<printed secret>'
curl -sS -H "authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:9571/api/v1/server | jq
# Now re-issue tokens for each operator.
```

## §6 — Lost the EKV cookie / cluster identity

If `/var/lib/exdns/.cookie` is gone on every node, the cluster can't re-form. EKV doesn't auto-recover from total identity loss.

Action: treat this as §3 (restore from backup) — the backup includes the cluster identity bytes inside the EKV data dir. If you have no backup either, then it's §3 + §4: rebuild from zone files and re-issue all DNSSEC keys.

## §7 — Communications template

```
[STATUS] DNS service degraded — DR in progress

What:    <short description>
When:    <UTC timestamp>
Impact:  Some/all DNS lookups for <domain> may return
         SERVFAIL or stale answers.
ETA:     <best estimate; "investigating" is fine for the
         first 30 minutes>

Workaround: <if any — e.g. flush local resolver cache
            after recovery>
```

Update every 15 minutes during an active incident, even if the update is "no change".
