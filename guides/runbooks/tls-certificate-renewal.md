# Runbook — TLS certificate renewal (DoT, DoH, admin API)

ExDns terminates TLS for three things:

* **DoT** (`ExDns.Listener.DoT`, port 853)
* **DoH** (`ExDns.Listener.DoH`, port 443)
* **Admin API** (when `:ex_dns, :api, [tls: true]` — optional)

All three read `:certfile` and `:keyfile` from their listener config. Renewing the certificate is the same recipe in all three cases: replace the files on disk, then signal the listener to reload.

## When to renew

Cert lifetime varies by issuer:

| Issuer | Typical lifetime | Renewal trigger |
|---|---|---|
| Let's Encrypt | 90 days | At 60 days (`certbot` default) |
| Internal CA | 1–2 years | One month before expiry |
| Public CA (DigiCert / Sectigo) | 1 year | One month before expiry |

Renewal must complete **before** the cert hits the leaf TTL CDNs cache for OCSP — practically, do it at least a week early.

## Pre-flight check

```bash
# What's the current cert's expiry?
openssl x509 -in /etc/exdns/tls/cert.pem -noout -dates

# What does the live listener actually present?
echo | openssl s_client -connect ns1.example.com:853 -servername ns1.example.com 2>/dev/null \
  | openssl x509 -noout -dates -subject -issuer
```

Discrepancy between "what's on disk" and "what's served" means the listener hasn't been restarted since the file changed. That's an alert.

## Renew with Let's Encrypt + certbot

```bash
# 1. Run certbot. The DNS-01 challenge is the cleanest for
#    a DNS server — needs a TXT record published in the same
#    zone the cert is for.
sudo certbot certonly \
  --dns-rfc2136 \
  --dns-rfc2136-credentials /etc/letsencrypt/exdns-rfc2136.ini \
  -d ns1.example.com \
  -d ns2.example.com \
  --post-hook "/usr/local/sbin/exdns-cert-deploy.sh"
```

The `dns-rfc2136` plugin uses TSIG-protected dynamic UPDATE — exactly what ExDns supports natively (see [guide 08](../08-secondary-zones-axfr-ixfr-notify.md) for the TSIG setup). The key in `/etc/letsencrypt/exdns-rfc2136.ini` should be a dedicated TSIG key with `:update_acls` scoped to the `_acme-challenge.*` subdomains only.

The post-hook script:

```bash
#!/usr/bin/env bash
# /usr/local/sbin/exdns-cert-deploy.sh
set -euo pipefail

LE_DIR=/etc/letsencrypt/live/ns1.example.com
TARGET=/etc/exdns/tls

install -d -o root -g exdns -m 0750 ${TARGET}
install -m 0640 -o root -g exdns "${LE_DIR}/fullchain.pem" "${TARGET}/cert.pem"
install -m 0640 -o root -g exdns "${LE_DIR}/privkey.pem"   "${TARGET}/key.pem"

# Trigger the listeners to re-read.
/opt/exdns/bin/exdnsctl tls reload
```

## Renewing without certbot (manual or other ACME client)

The mechanics:

1. Place the new cert at the path your `runtime.exs` references (`certfile`).
2. Place the new key at `keyfile`. Mode `0640`, owned by `root:exdns`.
3. Run `bin/exdnsctl tls reload`. Listeners re-read from disk on next handshake; existing connections stay on the old cert until they close.

## Verifying after renewal

```bash
# 1. The serving cert is fresh.
echo | openssl s_client -connect ns1.example.com:853 -servername ns1.example.com 2>/dev/null \
  | openssl x509 -noout -dates

# 2. DoT + DoH still answer.
kdig +tls @ns1.example.com example.com SOA
curl --doh-url https://ns1.example.com:443/dns-query \
     --resolve ns1.example.com:443:127.0.0.1 \
     example.com

# 3. No TLS handshake errors in the log.
journalctl -u exdns --since '5 minutes ago' | grep -i tls
```

## Troubleshooting

* **`exdnsctl tls reload` returns "no listener to reload"**: TLS isn't enabled. Either DoT / DoH is off, or the certfile/keyfile paths in runtime.exs are wrong.

* **Listener serves the old cert after reload**: Existing TCP/TLS connections aren't terminated by reload — only new connections see the new cert. Verify with a fresh `openssl s_client`. To force, `systemctl restart exdns` (drains then restarts).

* **`certbot --post-hook` fires but listener doesn't pick up**: The hook ran as root but the cert files ended up mode 0600 owned by root, unreadable by the `exdns` user. Set `0640` and `root:exdns`.

* **Cert renewal succeeded but resolvers report `BAD_CERT`**: The cert chain is missing an intermediate. Use `fullchain.pem` (not `cert.pem`) from Let's Encrypt.

## Drill: simulate cert expiry

Once a year, in staging:

```bash
# Backdate the cert to 1 hour past expiry.
fakeroot openssl x509 -in cert.pem -days -1 -signkey key.pem -out expired.pem
sudo cp expired.pem /etc/exdns/tls/cert.pem
sudo /opt/exdns/bin/exdnsctl tls reload

# Verify clients get a clear error rather than silently
# accepting the bad cert.
echo | openssl s_client -connect localhost:853 -verify_return_error
```

Then revert. If the team can't recover the staging env in under 10 minutes, the production runbook is wrong — fix it.
