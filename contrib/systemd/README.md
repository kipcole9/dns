# systemd integration for ExDns

## What's here

* `exdns.service` — production-grade Type=notify unit with
  filesystem hardening, capability scoping (CAP_NET_BIND_SERVICE
  only), watchdog + graceful drain.

## Install

```bash
# 1. Create the runtime user.
sudo useradd --system --home /var/lib/exdns --shell /usr/sbin/nologin exdns

# 2. Drop the release tarball into /opt/exdns.
sudo mkdir -p /opt/exdns
sudo tar -xzf ex_dns-0.1.0.tar.gz -C /opt/exdns
sudo chown -R root:root /opt/exdns
sudo chmod -R a-w /opt/exdns

# 3. Create config + state dirs.
sudo install -d -o exdns -g exdns -m 0750 /var/lib/exdns
sudo install -d -o root -g exdns -m 0750 /etc/exdns
sudo install -d -o root -g exdns -m 0750 /etc/exdns/zones.d

# 4. Drop your runtime config in place.
sudo cp config/runtime.exs.example /etc/exdns/runtime.exs
sudo $EDITOR /etc/exdns/runtime.exs

# 5. Install the unit.
sudo cp contrib/systemd/exdns.service /etc/systemd/system/exdns.service
sudo systemctl daemon-reload
sudo systemctl enable --now exdns

# 6. Verify.
systemctl status exdns
journalctl -u exdns -f
```

## Health probes

ExDns exposes `/healthz` and `/readyz` on the dedicated health
port (default 9572). systemd doesn't probe these directly —
sd_notify READY/STOPPING/WATCHDOG signals from `ExDns.SystemD`
drive the unit's lifecycle. The HTTP probes are for external
load balancers / Kubernetes / monitoring systems.

## Multi-node clusters

Set `RELEASE_NODE=exdns@$(hostname)` and a shared cookie on every
member, with `RELEASE_COOKIE_FILE` pointing at the same value
(file on disk, mode 0400, owned by `exdns`). Then:

```bash
cat /var/lib/exdns/.cookie    # same on every node
# RELEASE_NODE differs per host
```

EKV peer discovery is via libcluster — configure it under
`:libcluster` in `runtime.exs` (see runtime.exs.example).
