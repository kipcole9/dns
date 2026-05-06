# Fly.io deployment cookbook

End-to-end recipe for the **elixir-dns-test.com** test
deployment. The longer-form rationale and graduation
path live in
[`plans/fly_io_initial_deploy.md`](../../plans/fly_io_initial_deploy.md);
this file is the operator's checklist.

## Files in this directory

* `runtime.exs` — the Fly-specific runtime config baked
  into the image at `/opt/exdns/etc/runtime.exs`.
* `zones.d/elixir-dns-test.com.zone` — initial zone with
  `__FLY_PUBLIC_V4__` / `__FLY_PUBLIC_V6__` placeholders
  substituted at build time.

Files at the repo root that drive the deploy:

* `fly.toml` — Fly app config.
* `Dockerfile` — multi-stage build; the runtime stage
  includes the Fly-specific COPY + sed substitution.

## One-time setup

```bash
cd ~/Development/dns

# 1. Create the Fly app + 3 GB volume.
fly apps create exdns-test --org personal
fly volumes create exdns_state --app exdns-test --region lhr --size 3 --yes

# 2. Allocate a dedicated v4 (UDP requires it) + v6.
fly ips allocate-v4 --app exdns-test
fly ips allocate-v6 --app exdns-test

# 3. Capture the IPs you'll need for the build args + Cloudflare glue.
fly ips list --app exdns-test
# TYPE  ADDRESS              REGION  CREATED AT
# v4    a.b.c.d              global  …
# v6    2a09:8280:1::a:bcde  global  …

# 4. Set the per-deployment secrets.
fly secrets set --app exdns-test \
  RELEASE_COOKIE="$(openssl rand -hex 32)" \
  EXDNS_PUBLIC_NS="ns1.elixir-dns-test.com" \
  EXDNS_NSID="exdns-test-fly-lhr"
```

## Deploy

The zone file ships with `__FLY_PUBLIC_V4__` /
`__FLY_PUBLIC_V6__` placeholders so the IPs aren't
committed to git. Pass them as build args:

```bash
FLY_V4=$(fly ips list --app exdns-test | awk '/^v4/  {print $2}')
FLY_V6=$(fly ips list --app exdns-test | awk '/^v6/  {print $2}')

fly deploy \
  --app exdns-test \
  --remote-only \
  --build-arg FLY_PUBLIC_V4="${FLY_V4}" \
  --build-arg FLY_PUBLIC_V6="${FLY_V6}"
```

`--remote-only` builds on Fly's own builders so the EKV
NIF compiles against the runtime libc.

If you'd rather not type the build-arg dance every time,
drop this in `bin/fly-deploy`:

```bash
#!/usr/bin/env bash
set -euo pipefail
APP="${1:-exdns-test}"
FLY_V4=$(fly ips list --app "${APP}" | awk '/^v4/  {print $2}')
FLY_V6=$(fly ips list --app "${APP}" | awk '/^v6/  {print $2}')
exec fly deploy \
  --app "${APP}" \
  --remote-only \
  --build-arg FLY_PUBLIC_V4="${FLY_V4}" \
  --build-arg FLY_PUBLIC_V6="${FLY_V6}"
```

Then `bin/fly-deploy` is the only command anyone needs to
run.

## Verify (before flipping NS at Cloudflare)

```bash
PUBLIC_IP=$(fly ips list --app exdns-test | awk '/^v4/ {print $2}')

# 1. Authoritative SOA, AA=1.
dig @${PUBLIC_IP} elixir-dns-test.com SOA

# 2. NS record served from inside the zone.
dig @${PUBLIC_IP} elixir-dns-test.com NS +short

# 3. Glue lookup returns the Fly v4.
dig @${PUBLIC_IP} ns1.elixir-dns-test.com A +short

# 4. NSID echoes "exdns-test-fly-lhr".
dig @${PUBLIC_IP} elixir-dns-test.com SOA +nsid

# 5. NXDOMAIN with AA=1.
dig @${PUBLIC_IP} nope.elixir-dns-test.com A

# 6. TCP works.
dig @${PUBLIC_IP} elixir-dns-test.com SOA +tcp
```

If any of the six fails, **don't change Cloudflare's
NS records yet**. SSH into the machine and investigate:

```bash
fly ssh console --app exdns-test
# inside:
journalctl --no-pager | tail -200       # or /opt/exdns/bin/exdnsctl status
```

## Cloudflare delegation (after the six dig checks pass)

1. Cloudflare dashboard → **Domain Registration** →
   **Custom Nameservers** → add
   `ns1.elixir-dns-test.com` → IPv4 `${PUBLIC_IP}`,
   IPv6 `${PUBLIC_IP_V6}`.
2. Wait ~30 minutes; verify with
   `dig @a.gtld-servers.net ns1.elixir-dns-test.com A`.
3. Cloudflare dashboard → **Domain Registration** →
   **Nameservers** → change from
   `xxx.ns.cloudflare.com` to `ns1.elixir-dns-test.com`.
4. Save. Wait ~1 hour for parent-zone propagation.
5. Verify from a public resolver:
   `dig @8.8.8.8 elixir-dns-test.com SOA +trace`.

Full walkthrough including Cloudflare screen names lives
in [`guides/04-delegating-your-domain.md`](../../guides/04-delegating-your-domain.md).

## Day-to-day operations

| Task | Command |
|---|---|
| Tail logs | `fly logs --app exdns-test` |
| Open a shell | `fly ssh console --app exdns-test` |
| Run admin CLI | `fly ssh console --app exdns-test -C "/opt/exdns/bin/exdnsctl status"` |
| Issue an API token | `fly ssh console --app exdns-test -C "/opt/exdns/bin/exdnsctl token issue --role zone_admin --scopes '*'"` |
| Pull a backup of state | `fly ssh console --app exdns-test -C 'tar --use-compress-program=zstd -cf - -C /var/lib/exdns .' > exdns-backup-$(date -u +%Y-%m-%dT%H-%M-%SZ).tar.zst` |
| Restart (drains gracefully) | `fly machine restart --app exdns-test` |
| Scale memory | `fly scale memory 1024 --app exdns-test` |

## Editing the zone after deploy

Two paths:

* **Through the API** — `POST /api/v1/zones/elixir-dns-test.com/records`
  via `fly ssh console -C "curl ..."` or by SSH-tunnelling
  port 9571. Changes land in EKV on the volume; survive
  restart. **This is the operator path.**

* **By committing a new `zones.d/*.zone` + `fly deploy`**
  — useful for big bootstrap changes. The new file
  overrides any same-apex zone in EKV on next boot.

## Cost estimate

| Item | Approx monthly |
|---|---|
| `shared-cpu-1x` machine, always-on | $1.94 |
| 512 MB RAM | included |
| 3 GB volume | $0.45 |
| Dedicated IPv4 | $2.00 |
| IPv6 | $0.00 |
| Outbound bandwidth (low traffic) | < $1 |
| **Total** | **≈ $5–7 / month** |

Numbers from Fly's pricing page at time of writing —
verify before you provision.

## Tear-down

```bash
fly volumes destroy <vol_id> --app exdns-test --yes
fly apps destroy exdns-test --yes
```

Cloudflare side: revert the NS records to Cloudflare's
defaults (re-import any records you want to keep), and
delete the custom nameserver registration.
