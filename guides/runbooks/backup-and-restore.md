# Runbook — backup & restore

## What's worth backing up

| Path | What's in it | Backup cadence |
|---|---|---|
| `/var/lib/exdns/ekv/` | Zone records, plugin registry, TSIG keys, DNSSEC keys, BlackHole storage. The whole runtime state of the server. | Hourly snapshots, daily off-site copy. |
| `/var/lib/exdns/snapshot.bin` | Optional belt-and-braces zone snapshot (RFC 2136 UPDATEs, AXFR, catalog applies). EKV already has this state; the snapshot is a parallel copy. | Same as EKV. |
| `/var/lib/exdns/tokens.json` | Bearer-token registry. Hashed at rest (T1.4) — leaking the file can't authenticate against the API but does expose token metadata. | After every issue / revoke. |
| `/etc/exdns/runtime.exs` | Operator config. | On change (commit to a config-management repo). |
| `/etc/exdns/zones.d/*.zone` | Source zone files (loaded on start). | On change (commit to git). |

The **only file required to fully restore** the running state is the EKV data directory. Everything else is either operator config (re-deployable from your CM system) or convenience.

## Hourly backup script

```bash
#!/usr/bin/env bash
set -euo pipefail

DEST=/srv/backup/exdns
SRC=/var/lib/exdns
TS=$(date -u +%Y-%m-%dT%H-%M-%SZ)

install -d -o root -g root -m 0700 "${DEST}"

# Quiesce: take a consistent snapshot. The recommended way is
# to flush an LWW write (forces EKV to fsync), then copy the
# directory.
sudo -u exdns /opt/exdns/bin/exdnsctl ekv flush || true

tar --use-compress-program='zstd -T0' \
    -cf "${DEST}/exdns-${TS}.tar.zst" \
    -C "${SRC}" ekv snapshot.bin tokens.json

# Off-site copy — adjust to your storage.
rclone copy "${DEST}/exdns-${TS}.tar.zst" remote:exdns/$(date -u +%Y/%m/%d)/

# Local rotation: keep 24 hourly + 7 daily.
find "${DEST}" -mtime +1 -name 'exdns-*.tar.zst' -delete
```

Schedule via systemd timer:

```ini
# /etc/systemd/system/exdns-backup.timer
[Unit]
Description=Hourly ExDns backup

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/exdns-backup.service
[Unit]
Description=ExDns backup
After=exdns.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/exdns-backup.sh
```

## Restore on the same host

```bash
# 1. Stop the service. Drains in-flight queries first.
sudo systemctl stop exdns

# 2. Move the bad state aside (don't delete — you might
#    need it for forensics).
sudo mv /var/lib/exdns/ekv /var/lib/exdns/ekv.broken-$(date +%s)

# 3. Restore.
sudo tar --zstd -xf /srv/backup/exdns/exdns-2026-05-06T11-00-00Z.tar.zst \
         -C /var/lib/exdns
sudo chown -R exdns:exdns /var/lib/exdns

# 4. Bring the service back up.
sudo systemctl start exdns

# 5. Verify.
dig @127.0.0.1 example.com SOA +short
sudo /opt/exdns/bin/exdnsctl status
```

## Restore on a fresh host

Same as above, plus:

```bash
# Replay your config-management.
sudo cp $REPO/etc/exdns/runtime.exs /etc/exdns/
sudo cp $REPO/etc/exdns/zones.d/*.zone /etc/exdns/zones.d/

# Rejoin the EKV cluster (multi-node deployments only). The
# restored data dir already includes the cluster identity;
# bring up the node and EKV will sync recent writes from the
# remaining members.
sudo systemctl start exdns
```

## Multi-node cluster: restoring **one** node

If you lose a single node in a 3-node cluster, the surviving 2 retain quorum and keep serving. To replace the lost node:

1. Provision the new host (same hostname, same IP, or update peer list).
2. Install the release + the systemd unit.
3. **Don't** restore the EKV data dir from backup — start with an empty one. EKV will sync the full state from the surviving members on first boot.
4. Start the service. Watch `journalctl -u exdns -f` until you see `startup quorum reached`.

The "restore from backup" path is only for cluster-wide loss (every member's EKV data dir gone).

## Verifying a backup

A backup you've never restored is a wish, not a backup. Once a quarter:

```bash
# Spin up a sacrificial host or container.
docker run --rm -it \
  -v /srv/backup/exdns/latest.tar.zst:/restore.tar.zst:ro \
  -v exdns-restore-state:/var/lib/exdns \
  ghcr.io/kipcole9/ex_dns:latest \
  bash -c 'tar --zstd -xf /restore.tar.zst -C /var/lib/exdns && /opt/exdns/bin/ex_dns eval "ExDns.Storage.zones() |> Enum.each(&IO.puts/1)"'
```

The restored container should print every zone you expect to be present. If not, fix the backup before you need it for real.

## What can't be restored from backup

* **Lost DNSSEC private keys.** If the EKV backup includes them, you can restore. If not, you must roll the keys (operator-visible at the parent zone via DS update). See [DR runbook](disaster-recovery.md).
* **Bearer-token plaintext secrets.** Hashed at rest — on restore, every existing token still works (the hash is preserved), but if an operator forgot which secret a hash corresponds to, re-issue.
