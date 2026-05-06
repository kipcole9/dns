# 04 — Delegating your domain to ExDns (Cloudflare example)

You've registered `yourdomain.com` at a registrar. Right now the registrar's nameservers answer queries for it. You want **your** ExDns server(s) to be the answer instead.

This guide walks the full path: build the public zone in ExDns, expose the server to the internet, change the nameservers at the registrar (Cloudflare in the example), verify delegation, and harden the setup.

## Before you start

* **A registered domain.** This guide uses `yourdomain.com` — replace it everywhere.
* **At least one publicly-reachable host with a static IP.** Two is the minimum for a respectable production setup; for evaluation one is fine.
* **Port 53 open to the internet** on the host(s), both UDP and TCP. Yes, you need TCP — DNSSEC, AXFR, and large responses (EDNS truncation fallback) all use it.
* **Stable hostnames** for the nameservers, like `ns1.yourdomain.com` and `ns2.yourdomain.com`. These will be the names you register at the registrar.

> **Warning.** During the cut-over, DNS can take up to 48 hours to propagate (in practice, hours, not days). Don't change anything in production without a tested rollback plan and a monitoring window.

## Step 1 — Pick the public IPs

Decide what you want resolvers around the world to talk to:

| Hostname | Role | Public IP |
|---|---|---|
| `ns1.yourdomain.com` | Primary nameserver | `203.0.113.10` (replace) |
| `ns2.yourdomain.com` | Secondary nameserver | `203.0.113.11` (replace) |

If you only have one host, just use `ns1` and skip the secondary; you can add it later. Two is strongly recommended in production — most registrars require it.

## Step 2 — Build the zone

On your ExDns server, save this as `/etc/exdns/zones.d/yourdomain.com.zone`:

```dns
$TTL 3600
$ORIGIN yourdomain.com.
@           IN  SOA   ns1.yourdomain.com. hostmaster.yourdomain.com. (
                 2026010101 ; serial — bump on every edit
                 7200       ; refresh — secondary checks primary every 2h
                 3600       ; retry — on failure, retry every 1h
                 1209600    ; expire — secondary stops serving after 14d
                 3600 )     ; minimum — also negative-cache TTL

; Authoritative nameservers — these are advertised in the parent zone
            IN  NS    ns1.yourdomain.com.
            IN  NS    ns2.yourdomain.com.

; Glue records — the IPs of the nameservers themselves, served when they
; live inside the zone they're advertised for. Without these, resolvers
; can't bootstrap to your nameservers.
ns1         IN  A     203.0.113.10
ns2         IN  A     203.0.113.11

; Apex web records
@           IN  A     203.0.113.20
www         IN  A     203.0.113.20

; Mail
@           IN  MX    10 mail.yourdomain.com.
mail        IN  A     203.0.113.30

; Mail-related TXT records
@           IN  TXT   "v=spf1 mx -all"

; CAA — restrict who can issue certs for this domain
@           IN  CAA   0 issue "letsencrypt.org"
```

Reload via the API or restart the server:

```bash
TOKEN='<your zone_admin token>'

curl -sS -X POST http://127.0.0.1:9571/api/v1/zones/yourdomain.com/reload \
  -H "authorization: Bearer ${TOKEN}"
```

Verify locally:

```bash
dig @127.0.0.1 -p 53 yourdomain.com SOA
dig @127.0.0.1 -p 53 yourdomain.com NS
dig @127.0.0.1 -p 53 ns1.yourdomain.com A
```

All three should return `AA=1` (authoritative answer).

## Step 3 — Make sure the server is reachable

From a machine outside your network:

```bash
dig @203.0.113.10 yourdomain.com SOA
dig @203.0.113.10 yourdomain.com SOA +tcp
```

Both must succeed. If UDP works and TCP fails, your firewall is blocking TCP/53 — fix that first. If neither works, the server isn't bound to a public interface or the firewall is blocking the whole port.

## Step 4 — Register the nameserver hostnames at the registrar (Cloudflare)

Cloudflare is the registrar in this example. The mechanics are the same at most registrars; the menu names differ.

> **Important distinction.** Cloudflare has two products that both touch DNS: **Cloudflare Registrar** (where you registered the domain) and **Cloudflare DNS** (their hosted DNS service). This guide is for the case where you registered through Cloudflare but want **your ExDns server** to be the nameserver — not Cloudflare's. You will be **moving the domain off Cloudflare's nameservers**.

### 4a — Disable Cloudflare's DNS proxying

In the Cloudflare dashboard:

1. Open `yourdomain.com`.
2. Go to **DNS** → **Records**.
3. Take a screenshot of every existing record (you'll re-create the ones you need on your ExDns server, which you've already done in step 2).
4. Make sure no records are required by Cloudflare's other services (Workers, Pages, R2 custom domains, etc.). If they are, you'll need to either keep using Cloudflare DNS or re-create those bindings against your ExDns server.

### 4b — Register the nameserver glue ("vanity nameservers" / "child nameservers")

Because your nameservers live **inside** the zone they're delegating (`ns1.yourdomain.com` is itself a name in `yourdomain.com`), the registrar needs to publish their IP addresses in the parent zone (`com`). This is **glue**.

In the Cloudflare dashboard for the registered domain:

1. Open **DNS** → **Custom Nameservers** (sometimes labelled "Child Nameservers" or "Register Glue Records").
2. Add a record for each nameserver:
   * Hostname: `ns1.yourdomain.com` → IPv4: `203.0.113.10`
   * Hostname: `ns2.yourdomain.com` → IPv4: `203.0.113.11`

Cloudflare submits these to Verisign (the `.com` registry), which can take a few minutes to a few hours to propagate. Watch with:

```bash
dig @a.gtld-servers.net ns1.yourdomain.com A
```

Once that returns your IP, the glue is live.

### 4c — Change the authoritative nameservers

In the Cloudflare dashboard:

1. Go to **Domain Registration** → **Nameservers**.
2. Change from Cloudflare's defaults (`xxx.ns.cloudflare.com`) to:
   * `ns1.yourdomain.com`
   * `ns2.yourdomain.com`
3. Save.

This change goes to Verisign too. Cloudflare will warn you that you're moving DNS away from them. Confirm.

## Step 5 — Verify the delegation

From a machine that's not on your network, query a recursive resolver:

```bash
dig yourdomain.com SOA +trace
```

You should see the trace start at the root, hand off to a `.com` server, then hand off to **your** `ns1.yourdomain.com` (which the trace resolves through the glue you registered). The final answer should come from your ExDns server.

Confirm the answer is authoritative:

```bash
dig @ns1.yourdomain.com yourdomain.com SOA +norec
# status: NOERROR
# flags: qr aa
```

Run [DNSViz](https://dnsviz.net/) against `yourdomain.com` — it'll catch glue mismatches, missing NS records at the apex, EDNS issues, and DNSSEC chain-of-trust problems if you signed the zone.

## Step 6 — Harden it

* **Sign the zone with DNSSEC.** Generate a KSK and ZSK, register the DS at the registrar (Cloudflare → DNS → DNSSEC), then watch DNSViz turn green. See [07 — DNSSEC signing & rollover](07-dnssec-signing-and-rollover.md).
* **Run a real secondary.** A second physical host running ExDns in secondary mode, fed from the primary by AXFR / IXFR / NOTIFY. See [08 — Secondary zones](08-secondary-zones-axfr-ixfr-notify.md).
* **Restrict zone transfers.** By default ExDns refuses AXFR. Turn it on with a per-zone TSIG-protected ACL — never the default "allow any IP".
* **Rate-limit the listener.** Set `:rrl, enabled: true` to enable Response Rate Limiting (RFC token-bucket). Catches reflection-amplification abuse.
* **Drop privileges.** systemd unit + `User=exdns` + capability bind on port 53; never run the BEAM as root after the bind completes.

## Common issues

* **`SERVFAIL` from a recursor**: the resolver couldn't reach your nameservers. Likely glue is wrong or the firewall is blocking. `dig @8.8.8.8 yourdomain.com +trace` will show where the chain breaks.
* **Cloudflare keeps re-enabling proxying**: you have `proxied: true` records lingering at Cloudflare. Delete them or move all DNS off Cloudflare.
* **`REFUSED` from your own server**: the zone isn't loaded — check `mix exdns.ctl zone list` and the server log for validation errors.
* **DS record mismatch**: registrar's DS doesn't match the zone's DNSKEY. Re-extract the DS with `mix exdns.ctl key dnskey-to-ds` and re-submit at the registrar.

## Other registrars (the same recipe, different menus)

| Registrar | Where to set custom nameservers | Where to set glue records |
|---|---|---|
| Cloudflare | Domain Registration → Nameservers | DNS → Custom Nameservers |
| Namecheap | Domain List → Manage → Nameservers (Custom DNS) | Advanced DNS → Personal DNS Server |
| GoDaddy | Domain Settings → Manage Nameservers | Domain Settings → Host Names |
| Google Domains / Squarespace | DNS → Custom Records → Custom Nameservers | DNS → Glue Records |
| Gandi | Nameservers → External Nameservers | Glue Records |

The order is always the same: **glue first** (so the parent zone can resolve your NS hostnames), **then change the NS** (so the parent zone delegates to them).

## Related guides

* [01 — Installation, configuration & basic operations](01-installation-and-basic-operations.md)
* [05 — Zone management via curl](05-zone-management-via-curl.md) — for scripting the record updates.
* [07 — DNSSEC signing & rollover](07-dnssec-signing-and-rollover.md) — for the registrar DS handshake.
* [08 — Secondary zones, AXFR / IXFR / NOTIFY](08-secondary-zones-axfr-ixfr-notify.md) — for ns2.
