# Zone-file parser follow-ups

Real bugs found during the Fly.io scaffold work
(2026-05-06) that should be fixed before this build is
held up as a "BIND replacement" anywhere.

## Symptoms

Inputs that fail or hang against
`ExDns.Zone.File.process/1`:

| # | Input fragment | Result |
|---|---|---|
| 1 | `@ IN TXT "hello world"` | `{:error, {6, :zone_parser, [~c"syntax error before: ", [~c"\"TXT\""]]}}` |
| 2 | `@ IN CAA 0 issue "letsencrypt.org"` | `{:error, {6, :zone_parser, [~c"syntax error before: ", [~c"\"CAA\""]]}}` |
| 3 | `@ IN TXT "v=exdns-test; iter=1"` | **Hangs** (SIGTERM after 30 s; `;` inside the quoted TXT value puts the lexer in a state that doesn't terminate). |
| 4 | A blank line or `;`-only comment line **between** records | `{:error, {1, :zone_parser, [~c"syntax error before: ", [~c"\"\\n\""]]}}` |
| 5 | A `;`-only comment line **before** the first directive | Same error as #4 (multiple `\n` echoed). |

Discovery context: zone file at
`contrib/fly/zones.d/elixir-dns-test.com.zone` had to be
stripped of all blank lines, comment lines, TXT records
and CAA records to feed the parser cleanly. Anyone
operating from a BIND-shaped zone file would hit at
least #4 immediately.

## Root cause hypothesis

The grammar in `src/zone_parser.yrl` doesn't have rules
for `TXT` / `CAA` (and likely not for `SRV`, `NAPTR`,
`SVCB`, `HTTPS`, `TLSA`, `SSHFP`, `URI`, `LOC`, `DNSKEY`,
`DS`, `RRSIG`, `NSEC`, `NSEC3` either — verify with a
fuzz sweep). The lexer in `src/zone_lexer.xrl` may also
be eating `;` inside quoted strings as a comment
introducer, explaining #3.

The blank-line / comment handling appears to be
under-specified — either the grammar requires every
record to be on the directly-following line, or the
lexer emits `\n` tokens that the grammar rejects.

## Why this matters

* The Fly scaffold uncovered it, but every prospective
  operator runs into it the moment they import an
  existing BIND zone.
* TXT is mandatory for SPF / DKIM / DMARC / `_acme-challenge`
  / DS-record-style domain verification. Not having it
  in the static-loader path is a **major** gap.
* CAA is the simplest cert-issuance restriction — every
  zone with a TLS endpoint should have one.
* The hang on #3 is worse than the syntax error: a
  malicious or malformed zone file can stall the
  loader thread.

## Fix plan

| Priority | Task |
|---|---|
| **P0** | Lexer fix: `;` inside `"..."` is data, not a comment. Fuzz the lexer with quoted strings containing every printable character. |
| **P0** | Grammar fix: blank lines + `;`-only comment lines anywhere in the file are no-ops, including before the first directive. |
| **P1** | Add TXT to the grammar. Multiple character-strings on one record (`@ IN TXT "v=spf1" "-all"`) MUST work. |
| **P1** | Add CAA to the grammar. Three-tuple form (flags + tag + value). |
| **P2** | Audit every other record type defined in `lib/ex_dns/resource/*.ex` and add a grammar rule for any that's missing. SRV, NAPTR, SVCB, HTTPS, TLSA at minimum. |
| **P2** | Add a fuzz test (`test/ex_dns/fuzz/zone_file_grammar_fuzz_test.exs`) that generates plausible BIND-style zone files and asserts the parser accepts every record type the resource modules support. |
| **P3** | Add a corpus of real-world zone files (anonymised) under `test/fixtures/zones/` and a test that parses each one cleanly. |

## Workaround until fixed

The Fly scaffold (and any other deployment using the
static zone loader today) is constrained to:

* No blank lines or comment lines between records.
* No comment line before the first `$TTL` / `$ORIGIN`.
* A, AAAA, NS, SOA, CNAME, MX, PTR — the record types
  that **do** parse — only.
* Other records added at runtime via the HTTP API
  (`POST /api/v1/zones/<apex>/records`), which goes
  through a different code path that handles every type
  the Resource modules know about.

## Related fuzz coverage already in place

The Tier 2 zone-file parser fuzz
(`test/ex_dns/fuzz/zone_file_fuzz_test.exs`) catches
`raise`d crashes (UTF-8 was the example). It does NOT
catch:

* Hangs (because the property runs untimed inside the
  StreamData generator).
* Missing record-type coverage (because the generator
  doesn't produce TXT / CAA shapes).

The fuzz coverage needs to be extended as part of this
follow-up — add a per-property timeout and a generator
that produces every documented record type.
