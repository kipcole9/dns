# Real-world zone fixtures

Anonymised zone files that exercise the static-loader
parser in shapes that come from actual deployed zones.
The companion test
(`test/ex_dns/zone/file_corpus_test.exs`) loops every
`*.zone` file in this directory through
`ExDns.Zone.File.process/1` and asserts a clean parse.

This corpus is the regression backstop against the kind
of bug that broke the original Fly.io scaffold — a
combination of features that each work in isolation but
trip the parser when used together.

## Adding a fixture

1. Anonymise: replace real domain names, IPs, MX targets,
   DKIM public keys, etc with values from the documentation
   ranges (RFC 5737 IPs, RFC 6761 domains, base64 garbage).
2. Save as `test/fixtures/zones/<short-name>.zone`.
3. Run `mix test test/ex_dns/zone/file_corpus_test.exs` —
   the new file is auto-discovered.
4. If it doesn't parse, you found a bug. File it under
   `plans/zone_parser_followups.md`.

## Current corpus

| File | Exercises |
|---|---|
| `bind_style_full.zone` | BIND-style header comments, blank lines between sections, every common record type. |
| `dnssec_signed.zone` | A signed apex with DNSKEY, DS, RRSIG, NSEC. |
| `reverse_v4.zone` | An in-addr.arpa zone — PTR-heavy. |
| `txt_heavy.zone` | SPF, DKIM, DMARC, _acme-challenge, MTA-STS — TXT records with `;`, `=`, long base64 values. |
| `svcb_https.zone` | SVCB and HTTPS header records (params via API). |
