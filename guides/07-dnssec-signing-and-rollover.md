# 07 — DNSSEC signing & rollover

DNSSEC adds cryptographic signatures to your DNS answers so resolvers can detect tampering. ExDns implements both halves: **validation** of recursive answers and **signing** of authoritative ones, with a complete rollover state machine.

This guide covers signing — turning your zone into a DNSSEC-signed zone, registering the chain of trust at the parent (the registrar), then rolling keys safely.

## Concepts in 60 seconds

* **DNSKEY** — public-half signing key, published in your zone.
* **RRSIG** — signature attached to every other RRset in your zone, made with a DNSKEY's private half.
* **DS** — hash of your DNSKEY, published by the **parent zone** (your registrar). This is the chain of trust — resolvers find your DS at the parent, validate that against your published DNSKEY, then trust your RRSIGs.
* **KSK** (Key Signing Key) — signs only the DNSKEY RRset. Long-lived. Its hash is the DS at the registrar; rolling it requires updating the registrar.
* **ZSK** (Zone Signing Key) — signs everything else. Shorter-lived, rotated more often. Rolling it does **not** require touching the registrar.
* **NSEC / NSEC3** — proof of nonexistence. NSEC reveals the next existing name (zone walking is cheap); NSEC3 hashes names so it doesn't.

## Algorithm choice

ExDns supports the two algorithms you should be using in 2026:

| Algorithm | Why pick it |
|---|---|
| **ECDSAP256SHA256** (algo 13) | Universal validator support, small signatures, fast. Default. |
| **Ed25519** (algo 15) | Smaller, even faster, slightly less universal validator coverage. Pick when you control the resolvers or you're new and just want the modern thing. |

RSA-* are supported for compatibility with older zones; don't pick them for a new zone.

## Sign a zone

Generate a KSK and a ZSK for your zone, register them in the key store, and turn signing on:

```elixir
# config/runtime.exs
config :ex_dns,
  dnssec_zones: %{
    "example.com" => [
      denial: :nsec,            # or :nsec3
      algorithm: :ecdsap256sha256
    ]
  }
```

Generate keys with the CLI:

```bash
bin/exdnsctl key generate \
  --zone example.com \
  --role ksk \
  --algorithm ecdsap256sha256 \
  --state active

bin/exdnsctl key generate \
  --zone example.com \
  --role zsk \
  --algorithm ecdsap256sha256 \
  --state active
```

Both keys land in the EKV-backed `ExDns.DNSSEC.KeyStore` (replicated cluster-wide if you're running multi-node). The signer picks them up on the next signing pass.

Verify:

```bash
dig @127.0.0.1 -p 53 example.com SOA +dnssec
# Look for the RRSIG record alongside the SOA.
# flags: qr aa ad

dig @127.0.0.1 -p 53 example.com DNSKEY +short
# Two DNSKEY records — your KSK (flags 257) and ZSK (flags 256).
```

## Register the chain of trust at the registrar

Resolvers need to find your DS record at the parent zone (`com` for `example.com`). The registrar publishes it.

Extract the DS for your KSK:

```bash
bin/exdnsctl key dnskey-to-ds --zone example.com --role ksk
# example.com. IN DS 12345 13 2 ABCD1234...
```

Two columns matter: the **key tag** (`12345`) and the **digest** (the long hex string). The format your registrar wants varies, but it's always derived from this output.

### Cloudflare registrar

1. Cloudflare dashboard → your domain → **DNS** → **DNSSEC**.
2. Click **Add DS record** (or **Enable DNSSEC**, depending on the current state).
3. Fill in:
   * **Key tag** — `12345`
   * **Algorithm** — `13 (ECDSAP256SHA256)`
   * **Digest type** — `2 (SHA-256)`
   * **Digest** — the long hex string from `dnskey-to-ds`.
4. Save. Cloudflare submits to Verisign.

Allow up to a few hours for the DS to propagate. Verify with:

```bash
dig +trace example.com SOA
# The trace should show DS records in the .com response.

dig @8.8.8.8 example.com SOA +dnssec +adflag
# flags: qr rd ra ad     ← `ad` = "authenticated data" = chain validated
```

Run [DNSViz](https://dnsviz.net/) against your domain. Green is good; red triangles point at exactly where the chain is broken.

### Other registrars

Same recipe, different menu:

| Registrar | DS submission location |
|---|---|
| Cloudflare | DNS → DNSSEC |
| Namecheap | Advanced DNS → DNSSEC |
| GoDaddy | Domain Settings → DNSSEC |
| Gandi | DNSSEC tab |

## CDS / CDNSKEY auto-publication

ExDns publishes **CDS** and **CDNSKEY** records automatically. These are how a registrar that supports automated DS provisioning (per RFC 7344 / RFC 8078) discovers your current DS and updates the parent without you re-submitting it.

Cloudflare doesn't currently auto-poll CDS for registrar customers — you submit DS manually. But if you ever move to a registrar that does auto-poll (e.g. some `.cz` / `.se` / `.nl` registrars), your future ZSK and KSK rollovers become zero-touch at the parent.

## ZSK rollover (every 30–90 days)

A ZSK rollover uses the **pre-publication** scheme: stage the new key, wait for old DNSKEY caches to refresh, swap signing, retire the old key, wait for old signatures to expire, purge.

Phase by phase:

```bash
# 1. Prepare — generate a new ZSK in `incoming` state. It's
#    published in DNSKEY but not signing yet.
bin/exdnsctl key rollover example.com prepare --role zsk
# Note the printed `key_tag` of the new key.

# Wait one max-TTL of the DNSKEY RRset (default 3600s) so caches see it.

# 2. Activate — flip the new key to `active`. The signer
#    starts using it on the next signing pass. The old ZSK
#    stays active during the overlap.
bin/exdnsctl key rollover example.com active --role zsk --key-tag 12345

# Wait one max-TTL again so resolvers cache new RRSIGs.

# 3. Retire — flip the old ZSK to `retired`. It's still
#    published (so cached signatures validate) but no longer
#    used to sign new ones.
bin/exdnsctl key rollover example.com retire --role zsk --key-tag 67890

# Wait one max-TTL one more time so cached signatures expire.

# 4. Purge — remove the retired ZSK from the published
#    DNSKEY RRset.
bin/exdnsctl key rollover example.com purge --role zsk --key-tag 67890
```

The same operations are available on the API:

```bash
TOKEN='<cluster_admin token>'
api() {
  curl -sS -H "authorization: Bearer ${TOKEN}" \
       -H "content-type: application/json" "$@"
}

api -X POST http://127.0.0.1:9571/api/v1/keys/example.com/rollover/prepare \
    -d '{"role": "zsk"}'
api -X POST http://127.0.0.1:9571/api/v1/keys/example.com/rollover/active \
    -d '{"role": "zsk", "key_tag": 12345}'
api -X POST http://127.0.0.1:9571/api/v1/keys/example.com/rollover/retire \
    -d '{"role": "zsk", "key_tag": 67890}'
api -X POST http://127.0.0.1:9571/api/v1/keys/example.com/rollover/purge \
    -d '{"role": "zsk", "key_tag": 67890}'
```

…and there's a click-through wizard in the Web UI at the **Keys** tab.

## KSK rollover (every 1–5 years)

Same four phases as ZSK, **plus** a registrar handshake: when you `active` the new KSK, you need to register its DS at the parent and wait for the old DS to be removed before you `retire` the old KSK.

```bash
# 1. Prepare — generate a new KSK.
bin/exdnsctl key rollover example.com prepare --role ksk
# Note the new key tag.

# 2. Active — flip the new KSK to active.
bin/exdnsctl key rollover example.com active --role ksk --key-tag <new>

# 3. *** Now go to the registrar ***
#    Submit the DS for the new KSK alongside the old one
#    (most registrars accept multiple DS records).
bin/exdnsctl key dnskey-to-ds --zone example.com --role ksk --key-tag <new>
# Submit the printed DS at the registrar.

# Wait one parent-TTL (typically 24-48h for .com) so resolvers
# see both DS records.

# 4. Remove the old DS at the registrar.

# Wait another parent-TTL so the old DS is out of caches.

# 5. Retire the old KSK.
bin/exdnsctl key rollover example.com retire --role ksk --key-tag <old>

# Wait one DNSKEY-TTL.

# 6. Purge the old KSK.
bin/exdnsctl key rollover example.com purge --role ksk --key-tag <old>
```

This is the textbook **double-DS** rollover. Some operators prefer **double-KSK** (publish both KSKs, swap DS in one step) — the choice is yours; ExDns doesn't enforce one over the other.

## NSEC vs NSEC3 — pick one per zone

```elixir
config :ex_dns, :dnssec_zones, %{
  "public.example.com" => [denial: :nsec],
  "private.example.com" => [
    denial: :nsec3,
    salt: <<>>,             # or :crypto.strong_rand_bytes(8)
    iterations: 0,          # 0 is fine in 2026 (RFC 9276)
    opt_out: false
  ]
}
```

* **NSEC** — simpler, smaller, faster. Resolvers can walk the zone (extract every name). Use unless your zone contents are sensitive.
* **NSEC3** — names are hashed, zone walking is harder (not impossible). Use for zones where you don't want the contents enumerable.
* **NSEC3 opt-out** — NSEC3 records skip unsigned delegations. Useful for huge TLD-style zones with mostly insecure children. Never enable for normal end-user zones.

RFC 9276 strongly recommends `iterations: 0`. Higher iteration counts cost the validator more CPU and don't actually slow down zone walking by a meaningful factor.

## Operational checklist

* **Set DNSKEY TTL ≥ rollover wait time.** If your DNSKEY TTL is 3600s, every "wait one TTL" step is one hour. Keep the TTL short enough that rollovers don't take weeks.
* **Watch the validator's clock.** RRSIGs have signature inception and expiration timestamps; resolvers reject signatures more than a few minutes in the future or past. Run NTP.
* **Monitor expiry.** ExDns auto-resigns RRSIGs before they expire (default refresh window: 25% of remaining lifetime). Alert if signing falls behind — see [10 — Monitoring & observability](10-monitoring-and-observability.md).
* **Test recovery.** Stage a rollover in a staging zone, validate with DNSViz, then do production. Always.
* **Backup the keystore.** It's just rows in EKV; back up the EKV data directory.

## Disaster recovery

If you lose a private key, you cannot recover it — sign-with-it-or-lose-it. The mitigation is rolling keys regularly and keeping multiple **active** keys during the overlap (so a lost key reduces signing capacity but doesn't break validation).

If you lose **all** signing keys for a zone, you have two choices:

1. **Insecure-rollback.** Remove the DS at the registrar, wait one parent-TTL for it to clear caches, then either re-sign with new keys (and a fresh DS submission) or keep the zone unsigned.
2. **Restore from backup.** Stop the server, restore the EKV data directory from the most recent backup, restart. Lose any record changes since the backup.

Option 1 is the only safe path if you have no backup; serving signatures that don't validate will get your zone treated as `SERVFAIL` by every validating resolver.

## Related guides

* [04 — Delegating your domain](04-delegating-your-domain.md) — for the registrar context this guide assumes.
* [05 — Zone management via curl](05-zone-management-via-curl.md) — for the rollover endpoints.
* [10 — Monitoring & observability](10-monitoring-and-observability.md) — for signing-lag alerting.
