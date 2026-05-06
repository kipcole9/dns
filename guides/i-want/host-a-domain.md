# I want to host my own domain

For the small-business or hobbyist case. You registered
`yourdomain.com`, you want **your** server to answer
queries for it instead of the registrar's nameservers.

This is the path that ends with you running a public
authoritative DNS service, complete with DNSSEC + a real
secondary nameserver for redundancy.

## What you'll have when you're done

* `ns1.yourdomain.com` (and optionally `ns2`) point at
  your servers.
* The parent zone (`.com`) delegates to you, with glue.
* Your zone is signed with DNSSEC; the chain validates
  end-to-end.
* You can edit records via the web UI (or curl) and they
  propagate immediately.

## Steps

### 1. Install on your public-facing server

```bash
curl -fsSL https://raw.githubusercontent.com/kipcole9/dns/main/contrib/install/install.sh | sudo bash
```

The host needs:

* A static public IPv4.
* Port 53 (UDP + TCP) reachable from the internet.
* DNS PTR for the IP that resolves back to your nameserver
  hostname (your hosting provider sets this).

### 2. Wizard → "Host my own domain"

In the setup wizard, pick **Host my own domain** and click
through. You'll land on the dashboard with no zones yet.

### 3. Create the zone

From the sidebar: **Zones** → **+ Add zone**. Fill in:

* Domain: `yourdomain.com`
* Nameserver IPv4: the public IP of this server
* (Optional) IPv6, apex IP, SOA contact

Click **Create zone**. Behind the scenes the wizard
writes `/etc/exdns/zones.d/yourdomain.com.zone` and
loads it into the running server.

### 4. Verify it answers locally

```bash
dig @127.0.0.1 yourdomain.com SOA
```

You should get a SOA back with `aa` flag set.

### 5. Delegate at the registrar

The crucial step. Walk through
[guide 04: Delegating your domain](../04-delegating-your-domain.md)
end-to-end. The short version:

1. At the registrar, register **glue records** for
   `ns1.yourdomain.com` pointing at your server's IP.
2. **Wait** for the parent zone to publish them — usually
   30 minutes, sometimes hours.
3. **Then** change the authoritative nameservers from the
   registrar's defaults to `ns1.yourdomain.com`.
4. Wait again for parent-zone propagation.

### 6. Sign with DNSSEC (recommended)

Once the delegation is working, sign the zone:

* [Guide 07: DNSSEC signing & rollover](../07-dnssec-signing-and-rollover.md)
  walks through key generation and the registrar DS-record
  handshake.
* `exdns doctor` will warn you if your zone is configured
  for DNSSEC but missing keys.

### 7. Add a secondary nameserver

A second server on a different network is the standard
production setup. See
[guide 08: Secondary zones](../08-secondary-zones-axfr-ixfr-notify.md)
for the AXFR / IXFR / NOTIFY recipe.

## Day-to-day

Edit records via the UI's zone-detail page, or via the
API:

```bash
TOKEN=…
curl -sS -X POST -H "authorization: Bearer ${TOKEN}" \
  -H "content-type: application/json" \
  http://localhost:9571/api/v1/zones/yourdomain.com/records \
  -d '{"name":"www","type":"A","ttl":300,"data":"203.0.113.20"}'
```

`exdns zone reload yourdomain.com` re-reads the on-disk
file when you've edited that directly.

## When it goes wrong

* **`exdns doctor`** catches the obvious — missing SOA,
  missing apex NS, broken DNSSEC, expired certs.
* External validators are the next stop:
  [DNSViz](https://dnsviz.net/),
  [Zonemaster](https://zonemaster.net/), and
  [SSL Labs](https://www.ssllabs.com/ssltest/) for any
  TLS endpoint.
* `plans/external_validation_plan.md` documents the full
  pre-launch checklist.

## Where to go next

* [Guide 04: Delegating your domain](../04-delegating-your-domain.md)
* [Guide 07: DNSSEC](../07-dnssec-signing-and-rollover.md)
* [Guide 08: Secondaries](../08-secondary-zones-axfr-ixfr-notify.md)
* [Runbook: backup & restore](../runbooks/backup-and-restore.md)
* [Runbook: planned upgrade](../runbooks/planned-upgrade.md)
