# Zone-file parser follow-ups

> **STATUS: ALL OPEN ITEMS RESOLVED 2026-05-06.** P0 (lexer
> + grammar fixes), P1 (TXT, CAA), P2 (every other supported
> record type plus type-aware grammar fuzz), and P3
> (real-world zone corpus) are shipped.
>
> Regression coverage:
>
> * `test/ex_dns/zone/file_parser_fixes_test.exs` — the
>   four original bugs.
> * `test/ex_dns/fuzz/zone_file_grammar_fuzz_test.exs` —
>   one property runs every supported record type through
>   `process/1` with a per-iteration timeout (catches
>   parser hangs).
> * `test/ex_dns/zone/file_corpus_test.exs` — five
>   anonymised real-world zone fixtures under
>   `test/fixtures/zones/`.
>
> See the "Fix plan" table below for the per-item status.

Real bugs found during the Fly.io scaffold work
(2026-05-06) that blocked deploying a BIND-style zone file.

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

| Priority | Task | Status |
|---|---|---|
| **P0** | Lexer fix: `;` inside `"..."` is data, not a comment. | ✅ Done — quote-aware `remove_comments/1` in `lib/ex_dns/zone/file.ex`. Tested by `file_parser_fixes_test.exs` "fix #1". |
| **P0** | Grammar fix: blank lines + `;`-only comment lines anywhere in the file are no-ops, including before the first directive. | ✅ Done — leading-whitespace strip in `tokenize/1`. The lexer's `Newline` regex already consolidated mid-file blank lines. Tested by "fix #4". |
| **P1** | Add TXT to the grammar. Multiple character-strings on one record (`@ IN TXT "v=spf1" "-all"`) MUST work. | ✅ Done — TXT lexer rule, `txt_record` grammar rule with trailing `newline`, `TXT.new/1` bridge. Tested by "fix #2". |
| **P1** | Add CAA to the grammar. Three-tuple form (flags + tag + value). | ✅ Done — `caa` token, `caa_record` grammar rule, `CAA.new/1` bridge. Tested by "fix #3". |
| **P2** | Audit every other record type defined in `lib/ex_dns/resource/*.ex` and add a grammar rule for any that's missing. SRV, NAPTR, SVCB, HTTPS, TLSA at minimum. | ✅ Done — added grammar + `new/1` for **PTR, DNAME, TLSA, SSHFP, DS, CDS, DNSKEY, CDNSKEY, NAPTR, SVCB, HTTPS, LOC, RRSIG, NSEC, NSEC3** (15 record types). Also extended the lexer's `Service` regex to permit hyphens in `_`-prefixed labels (`_xmpp-server`, `_mta-sts`). The grammar exposes a shared `binary_blob` nonterminal for hex/base64 fields and a `type_name` nonterminal for the NSEC/NSEC3 type bitmaps. |
| **P2** | Add a fuzz test (`test/ex_dns/fuzz/zone_file_grammar_fuzz_test.exs`) that generates plausible BIND-style zone files and asserts the parser accepts every record type the resource modules support. | ✅ Done — `test/ex_dns/fuzz/zone_file_grammar_fuzz_test.exs`. One property × 50 iterations × 23 record types, each parsed inside a 1 s `Task.yield` so a regression to a parser hang fails the test rather than blocking forever. |
| **P3** | Add a corpus of real-world zone files (anonymised) under `test/fixtures/zones/` and a test that parses each one cleanly. | ✅ Done — five fixtures (`bind_style_full`, `dnssec_signed`, `reverse_v4`, `txt_heavy`, `svcb_https`) plus `test/ex_dns/zone/file_corpus_test.exs` that auto-discovers every `*.zone` and parses it. The corpus README explains the contributing recipe. |

## Workaround until fixed

(No longer needed — see status banner at the top.)

Two deliberate "minimal-form-only" gaps remain in the
static loader, both because the human-readable text form
is genuinely awful and operators almost universally use
either the API or generated output:

* **SVCB / HTTPS** — header form only. SvcParams (`alpn=`,
  `port=`, `ipv4hint=`) come via the HTTP API, which feeds
  the SVCB struct's `params` field directly.

* **LOC** — integer-form only (the seven wire-format
  fields). The RFC 1876 deg/min/sec `42 21 54 N 71 06 18 W
  -24m 30m 10m 10m` form is not yet parsed; use the API.

If a future operator hits one of these, file an issue and
we'll do the parser work.

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
