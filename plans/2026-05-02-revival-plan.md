# ExDns revival plan

Date: 2026-05-02
Author: kip + Claude

## Goals (unchanged from project inception)

* Native Elixir authoritative DNS resolver.
* Support all common resource record types (modern essential set + DNSSEC subset).
* Read **and** write zone files (round-trip).
* Keep an ETS table for in-memory zone resolution.
* Wire-format parsing and answer generation built on Elixir/OTP **bitstring pattern matching** — this architecture is load-bearing and must be preserved.

## Constraints

* **Minimum Elixir:** 1.17.
* **Development on:** Elixir 1.20 (currently 1.20.0-rc.4 / Erlang/OTP 28).
* **Transport (now):** UDP only.
* **Transport (future):** DNS over TCP (RFC 7766) and DNS over HTTPS (RFC 8484). The wire-format work in Phase 1 must produce a transport-neutral encoded message so that adding TCP framing or HTTPS POST bodies later does not require rework.
* **No third-party DNS libraries.** No parser combinators (nimble_parsec, etc.) for wire format. Yecc/Leex for the zone-file *text* format is fine and already in place.

## Current state (audit, 2026-05-02)

| Area | State |
|---|---|
| Build | **Broken.** 3 fatal compile errors: `class_from/1` imported but undefined in `lib/ex_dns/resource/{a,cname,mx}.ex`; undefined `type` var in `A.encode`. |
| Wire decode | Header + question parsing works in `lib/ex_dns/message.ex`. **No RDATA dispatch** to per-type modules. |
| Wire encode | `Message.encode/1` is a no-op. `A.encode` is the only RR-level attempt and is broken. |
| Resource modules | A, AAAA, NS, CNAME, SOA, MX, TXT, PTR, SRV, HINFO, OPT exist as files. Most contain only `format/1` (zone-file text rendering). OPT is a 128-line comment block. TXT is a 3-line stub. |
| Zone parser (text → records) | **Working.** Yecc/Leex pipeline. Handles A, AAAA, NS, SOA, MX, CNAME, SRV, HINFO, TXT, URI. |
| Zone writer (records → text) | **Missing.** No round-trip. |
| Storage | `ExDns.Storage.ETS` is 18 lines of empty function heads. `ExDns.Zone` is a 20-line struct. |
| UDP listener | Receives, dispatches to poolboy worker pool. Worker calls a stub resolver that returns `{1,2,3,4}` and `IO.inspect`s instead of replying. |
| TCP listener | Not implemented. |
| EDNS0 (OPT) | Not wired in. |
| Tests | 7 zone-parser tests. Zero wire-format or resolver tests. |
| Modern RR coverage | ~11/25 essential types present at any level. Missing: CAA, DS, DNSKEY, RRSIG, NSEC, NSEC3, NAPTR, TLSA, SVCB, HTTPS, DNAME, LOC, SSHFP, URI (URI parsed but no module). |

## Plan — seven phases

### Phase 0 — Get it green
1. Add public `class_from/1` (and likely `type_from/1`) helpers in `lib/ex_dns/resource.ex`.
2. Fix `A.encode` — `type` should resolve through `type_from/1`.
3. Bump `mix.exs`: `elixir: "~> 1.17"`, modernise project options, add `compilers: [:leex, :yecc] ++ Mix.compilers()`.
4. Replace `Supervisor.Spec.worker/3` with child specs in `lib/ex_dns/application.ex`.
5. Migrate `config/*.exs` from `Mix.Config` to `Config`.
6. Replace `use Bitwise` with `import Bitwise` in `lib/ex_dns/inet_utils.ex`.
7. Charlist literal cleanup (`'foo'` → `~c"foo"`) where it appears.
8. Add `:ex_doc`, `:dialyxir`, `:credo` as dev deps. (Do not add `:nimble_parsec`.)

**Exit criteria:** `mix compile` clean, `mix test` passes (zone parser tests still green).

### Phase 1 — Real wire-format round-trip

This is the most architecturally important phase.

1. Define `ExDns.Resource` behaviour:
   * `@callback decode(rdata :: binary, message :: binary) :: struct` — `message` passed so name-compression pointers resolve.
   * `@callback encode(struct, offsets :: map) :: {iodata, offsets}` — accumulator pattern so name compression works on the way out.
   * `@callback format(struct) :: iolist` — zone-file text rendering.
2. Centralise type↔atom mapping (A=1, NS=2, …) and class↔atom mapping in `ExDns.Resource`. Public `type_from/1`, `type_for/1`, `class_from/1`, `class_for/1`.
3. Wire RDATA dispatch into `Message.decode`: after reading `type`, `class`, `rdlength`, slice `rdata::binary-size(rdlength)` and call the right resource module's `decode/2`.
4. Implement `decode/encode` for each existing RR using bitstring pattern:
   * **A** — `<<a, b, c, d>>`
   * **AAAA** — `<<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>`
   * **NS, CNAME, PTR, DNAME** — single compressed name
   * **SOA** — mname, rname, serial::32, refresh::32, retry::32, expire::32, minimum::32
   * **MX** — preference::16, exchange (name)
   * **TXT** — sequence of `<<len::8, str::binary-size(len)>>`
   * **SRV** — priority::16, weight::16, port::16, target (name)
   * **HINFO** — two character-strings
5. Implement `Message.encode/1` for real:
   * Rebuild header flags as a bitstring.
   * Concatenate question + answer + authority + additional sections.
   * Name-compression: maintain an offsets map across the encode pass; emit `<<0b11::2, offset::14>>` pointers when an already-seen suffix is encountered.
   * Output is **transport-neutral iodata** — no UDP/TCP/HTTPS framing here. The transport layer (currently `ExDns.Listener.UDP`, later `Listener.TCP` and `Listener.HTTPS`) is responsible for any length-prefixing, MTU truncation (TC flag), or HTTP framing.
6. Tests: round-trip `Message` struct → `encode` → `decode` → equal struct, for each RR type. Use bytes captured from `dig +qr +noedns` as ground truth where useful.

**Exit criteria:** Round-trip equality for every implemented RR type. The transport-neutral split is the bridge to future TCP and DoH support.

### Phase 2 — Storage and authoritative lookup
1. Build out `ExDns.Storage.ETS`:
   * One named ETS table per zone.
   * Index table mapping zone-apex → table.
   * Key: `{normalized_name, type}`. Value: list of resource records (an RRset).
2. Build out `ExDns.Zone`: `load_file/1` takes a zone-file path, uses the existing Yecc parser, inserts each RR into the zone's ETS table.
3. Replace `Resolver.Default` with real authoritative resolution:
   * Longest-suffix zone match.
   * Exact RRset lookup.
   * Wildcard (`*.foo`) per RFC 4592.
   * CNAME chasing within zone.
   * NS delegation (return AUTHORITY + glue ADDITIONAL).
   * Correct NXDOMAIN vs NODATA distinction.
   * Set AA flag on authoritative responses.
4. Wire `Resolver.Worker` to actually `:gen_udp.send/4` the encoded reply.

**Exit criteria:** `dig @127.0.0.1 -p 5353 <name> <type>` returns the correct record set with proper flags against the loaded test zones.

### Phase 3 — EDNS0 (OPT) and `dig` integration tests
1. Implement OPT properly: UDP payload size, extended-rcode, version, flags; option list (NSID, COOKIE, ECS).
2. Have `Header` use the OPT-extended rcode when present.
3. Add `test/integration/dig_test.exs` that boots the supervisor on port 5353, runs `dig` via `System.cmd`, and asserts on parsed output. Cover: `+noedns`, default (EDNS0), `ANY`, `+nsid`, NXDOMAIN, wildcard, CNAME chase.

### Phase 4 — Zone file writer (round-trip)
1. `ExDns.Zone.File.serialize/1` — `%Zone{}` → zone-file iodata, using each module's `format/1`.
2. Round-trip property tests: parse → serialize → parse → assert structurally equal. Will surface `format/1` bugs.

### Phase 5 — Modern RR coverage
Order by effort × value:

* **Easy:** CAA, DNAME, SSHFP, NAPTR, URI, LOC, TLSA.
* **DNSSEC (serve-only, no signing):** DS, DNSKEY, RRSIG, NSEC, NSEC3.
* **Newer:** SVCB, HTTPS (RFC 9460).

Each new type follows the Phase 1 template plus a Yecc grammar rule extension.

### Phase 6 — Additional transports
1. **TCP listener** (RFC 1035 §4.2.2 + RFC 7766) — length-prefixed messages. Wire `Resolver.Worker` so it doesn't care about transport.
2. **TC flag fallback** — UDP responses larger than the negotiated EDNS0 buffer get truncated with TC=1; client retries over TCP.
3. **DoH listener** (RFC 8484) — HTTP/1.1 + HTTP/2 endpoint accepting `application/dns-message` over POST and GET. Bandit or Plug.Cowboy as the HTTP server (decision deferred to that phase).
4. **AXFR** (RFC 5936) and **IXFR** (RFC 1995) over TCP. **NOTIFY** (RFC 1996).

### Phase 7 — Polish for release
* Function and module docs to the standard template (`### Arguments / ### Options / ### Returns / ### Examples`).
* `mix dialyzer` clean.
* README rewrite — current README advertises capability that does not exist.
* CHANGELOG and version bump.

## Decisions captured for later phases

* **Transport-neutral message encoding:** The Phase 1 encoder must return iodata that is identical regardless of UDP / TCP / HTTPS. Framing (TCP length prefix, HTTP body) lives in transport modules.
* **No DNSSEC signing in scope.** The library will be able to serve pre-signed zones (parse and emit DNSSEC RRs verbatim) but signing key management and zone-signing are deliberately out of scope for the foreseeable plan.
* **Pluggable storage.** ETS is the default. The `ExDns.Storage` interface should be extractable into a behaviour later for alternative back-ends, but Phase 2 will hardcode ETS — premature abstraction is worse than a later refactor.
