# Ease-of-setup remediation plan

## The two bars we're shooting for

ExDns is being measured against the operators on either
end of the DNS-server spectrum. The product needs to clear
**both** bars without compromising either.

### The pi-hole user

Naive operator. Probably technical (knows how to ssh into
a Raspberry Pi) but doesn't read RFCs and has never typed
a SOA serial. Their full mental model is "I want my LAN
to use this thing and it should block ads."

What they expect:

* **One-line install.** `curl -fsSL … | bash`. 5 minutes
  to a working server.
* **Web UI is the entire surface.** They never touch a
  config file.
* **Sane defaults.** Useful out of the box; opt-in to the
  esoteric stuff.
* **First-run wizard.** Pick what you want, click, done.
* **Update path.** `pihole -up`. No tarballs.
* **Visible feedback.** "12 queries blocked in the last
  hour" on the homepage.

### The BIND operator

Power user. Reads RFCs for fun. Has a `named.conf` they
maintain in git. Expects every knob to exist and to be
configurable as code.

What they expect:

* **Config-as-code.** `runtime.exs` checked into git, no
  hidden state in the database that isn't reproducible
  from disk.
* **Real CLI.** `rndc`-equivalent, `named-checkconf`-
  equivalent, structured output for piping.
* **Robust clustering.** Primary/secondary or shared-state
  cluster, with documented failure modes.
* **Every record type.** AXFR / IXFR / NOTIFY interop
  with BIND, Knot, NSD, Cloudflare.
* **DNSSEC signing pipeline.** ZSK + KSK rollover, CDS
  publication, parent handshake.
* **TSIG-protected operations.** Transfers, dynamic
  updates, NOTIFY-receive.

## Where we are today

| Bar | Status |
|---|---|
| Pi-hole user can install in < 5 min | ❌ — no installer, no precompiled binary path, requires Elixir/Docker |
| Pi-hole user can configure entirely in the UI | ⚠️ — UI exists but assumes zones are loaded from disk; no "create your first zone" flow; no first-run wizard |
| Pi-hole user gets useful defaults | ⚠️ — `runtime.exs.example` is comprehensive but 200 lines of opt-in; no "minimal" preset |
| Pi-hole user gets a working ad-blocker out of the box | ❌ — BlackHole exists, but operator has to subscribe to lists, configure groups, choose CIDRs, all via API |
| BIND operator gets config-as-code | ✅ |
| BIND operator gets full CLI | ⚠️ — `bin/exdnsctl` wraps `mix exdns.ctl`, requires the project on disk; no standalone binary |
| BIND operator gets every record type | ✅ (after the parser sprint) |
| BIND operator gets DNSSEC | ✅ |
| BIND operator gets clustering | ⚠️ — EKV layer exists; multi-node tested only via the split-brain quorum check, not full operational story |

The gaps are mostly on the **pi-hole side**. The BIND side
is largely covered by what we already shipped.

## Friction inventory — what trips a pi-hole user today

Walking through "ssh into a fresh Raspberry Pi, want a
working DNS-with-ad-blocking" with the current build:

1. **No precompiled binaries.** Operator has to install
   Erlang + Elixir, or Docker, before anything. The
   release tarball ships ERTS but operators still need
   to know it exists and where to download from.

2. **No installer.** They'd have to: `wget` the tarball,
   `tar -xzf`, create a user, install systemd unit,
   `systemctl enable --now`. About 8 manual steps.

3. **Zones come from on-disk files.** A naive user has
   no idea what an SOA serial is, why they need an NS
   record, or what `$ORIGIN` does. The current API
   exposes record CRUD but the UI has no "create a zone
   from scratch" flow — every UI affordance assumes
   the zone already exists.

4. **API token bootstrap is CLI-only.** First-time setup
   is `mix exdns.token.issue`, which requires Mix,
   which requires the source tree. Even from the
   release tarball this isn't a one-click flow.

5. **UI user creation is also CLI-only.** `mix
   dns_ui.user.create` — same problem.

6. **No first-run wizard.** Open <http://localhost:4000>
   on a fresh install and you see a login screen with
   no way to create the first user.

7. **Default config does nothing useful.** Listener
   binds 0.0.0.0:53; no zones loaded; no recursor
   configured; no ad-blocking enabled. The operator has
   to know what they want and how to ask for it.

8. **Ad-blocking requires API moves.** BlackHole is the
   marquee feature for this audience and there's no UI
   path to "enable ad-blocking for my LAN":
   - Issue token via CLI
   - POST `put_blocklist` (find a URL)
   - POST `put_group` (figure out your CIDR)
   - POST `refresh_blocklist`
   - Wait, then test
   That's a lot of "figure out".

9. **No network detection.** Pi-hole detects the
   primary interface, computes its CIDR, suggests
   sensible upstream resolvers. ExDns doesn't do any
   of that; the operator types CIDRs into config.

10. **Update path is "rebuild and redeploy".** No
    `exdns update` command. `apt-get upgrade exdns` not
    a thing. Operators of small home setups won't run
    `mix release` themselves.

11. **No service detection / DHCP integration.** Pi-hole
    can be the LAN's DHCP server too. ExDns doesn't —
    intentional, but it means the operator has to also
    point their router's DHCP at the new server, which
    most pi-hole users don't know how to do.

12. **Documentation is comprehensive but daunting.**
    11 guides, 8 runbooks, 3 plans. A pi-hole user wants
    "click here to start". A BIND user appreciates the
    docs but they're not currently indexed by persona.

13. **No "delete me" recovery.** A pi-hole user who
    breaks their DNS can `pihole disable` and their
    queries fall back through the router. ExDns
    operators have to know to flip resolver config back.

14. **Mobile UI.** The Web UI uses LiveView + Tailwind
    and is responsive in principle, but no fixture has
    been verified at 375px width. A pi-hole user
    administers from their phone half the time.

## Tier 1 — installer + first-run UX (mandatory before launch)

The minimum viable bar for "pi-hole user" success.

### T1.1 — Precompiled binaries published per release

* **What**: GitHub Actions matrix build that emits
  `ex_dns-<version>-<os>-<arch>.tar.gz` for:
  * Linux x86_64 (Debian-bookworm-built — broadest libc
    compatibility).
  * Linux aarch64 (Raspberry Pi 4/5, AWS Graviton).
  * macOS arm64 (operator laptops for evaluation).
* **Where**: `.github/workflows/release.yml`, attached
  to GitHub Releases. Same approach as
  `image_qrcode` per CLAUDE.md NIF lessons.
* **Acceptance**: a Pi 4 user runs `wget && tar &&
  ./bin/ex_dns start` and gets a working server.

### T1.2 — One-line install script

* **What**: `bin/install.sh` hosted at a stable URL
  (e.g. `install.exdns.io` or in the GitHub repo's
  `contrib/install/`).
  ```bash
  curl -fsSL https://install.exdns.io | bash
  ```
* **The script**:
  1. Detects OS + arch.
  2. Downloads the matching precompiled tarball.
  3. Creates `exdns` user + group.
  4. Unpacks to `/opt/exdns`.
  5. Installs `contrib/systemd/exdns.service`.
  6. Sets `cap_net_bind_service` on the BEAM binary.
  7. Generates a fresh `RELEASE_COOKIE` into
     `/var/lib/exdns/.cookie`.
  8. Drops a minimal `runtime.exs` (see T1.4).
  9. Generates a one-time bootstrap token and writes it
     to `/root/exdns-bootstrap.txt` (mode 0600).
  10. `systemctl daemon-reload && systemctl enable
      --now exdns`.
  11. Prints: "Open <http://`hostname`:4000> and follow
      the on-screen wizard. Bootstrap code in
      `/root/exdns-bootstrap.txt`."
* **Acceptance**: from a fresh Debian/Ubuntu/Fedora/
  Alpine box, one curl pipe to a working install in
  under 60 seconds.

### T1.3 — First-run UI wizard (no pre-existing user)

* **What**: when the UI starts and `users.json` is
  empty, redirect every route to `/setup` instead of
  `/login`.
* **`/setup` flow**:
  1. **Welcome** — short copy.
  2. **Bootstrap code** — paste from
     `/root/exdns-bootstrap.txt`. Prevents random
     visitors from claiming the install.
  3. **Create admin** — email + password.
  4. **Pick your goal** — three radio buttons:
     * "Block ads on my LAN" (BlackHole)
     * "Resolve DNS for my LAN" (recursor only)
     * "Host my domain" (authoritative)
     * "All three" (combined)
  5. **Confirm settings** — show the auto-detected
     LAN CIDR (read from `/proc/net/route` or
     equivalent), confirm before applying.
  6. **Apply + redirect** to the main UI.
* **Where**: new `dns_ui_web/live/setup_live.ex` +
  setup-only Phoenix pipeline that's enabled only
  while the system is in setup mode.
* **Acceptance**: from "service running, no users" to
  "fully configured ad-blocker" in ≤ 5 UI clicks.

### T1.4 — Minimal opinionated `runtime.exs`

* **What**: a `config/runtime.exs.minimal` (or shipped
  as the actual default) that's 30 lines instead of
  200, and that **does the right thing** out of the
  box:
  * Listener on 53 / UDP+TCP, bound to the LAN
    interface only.
  * Recursion enabled, falling through to
    `1.1.1.1` and `9.9.9.9`.
  * EKV in single-node mode at `/var/lib/exdns/ekv`.
  * Admin API on 9571, loopback only.
  * All the Tier-1 abuse-mitigation defaults
    (RRL, cookies, per-IP cap) on.
  * BlackHole **disabled** by default — gets
    enabled by the wizard if the operator picks it.
* **Where**: `config/runtime.exs.minimal` plus a
  rename in `mix.exs` so the release tar embeds it
  as `runtime.exs`.
* **Acceptance**: a freshly-installed server with
  no operator config makes correct LAN-recursive
  answers immediately.

### T1.5 — Bootstrap token flow

* **What**: replace the "operator types `mix
  exdns.token.issue`" path with a one-time bootstrap
  code generated by the installer + consumed by the
  setup wizard.
* **Where**: a new `ExDns.Bootstrap` module that
  generates a single-use code on first boot, exposes
  it for the wizard to consume, and self-deletes
  after first successful use.
* **Acceptance**: operator never opens a terminal
  after running the install command.

### Tier 1 completion = launch gate

Without T1.1–T1.5 a pi-hole-class user cannot get a
running ad-blocker in 5 minutes. **All five are launch
blockers.**

## Tier 2 — UI flows that make the wizard's choice work

After the wizard picks a persona, the UI needs to
deliver. Today the existing UI is record-CRUD-shaped;
each persona needs a more direct surface.

### T2.1 — "Block ads on my LAN" preset

When the wizard picks this:

1. Auto-subscribe to a curated default list (Steven
   Black unified hosts).
2. Auto-create a group covering the detected LAN CIDR.
3. Bind the blocklist to the group.
4. Trigger an immediate refresh.
5. Land the operator on the BlackHole dashboard with
   a banner: "Ad-blocking is on for `<LAN-CIDR>`. Most
   recent blocked: `<example>`".

Pi-hole-equivalent in user terms: zero clicks after
"go".

**Code**: a new `ExDns.BlackHole.Bootstrap.enable_for_lan/1`
that does steps 1–4 atomically; the UI calls it.

### T2.2 — "Host my domain" zone-creation wizard

A guided flow that takes:

* Domain name (`example.com`).
* The IP this server should advertise as `ns1`.
* (Optional) The IP to point the apex at.

…and produces a working zone with SOA + NS + glue + a
sensible apex A. Saves the file under
`/etc/exdns/zones.d/<apex>.zone`, reloads, lands on
the zone-detail page.

**Code**: `ExDns.Zone.Bootstrap.create_authoritative_zone/2`
in lib/, plus a `/zones/new` LiveView in dns_ui.

### T2.3 — "Resolve DNS for my LAN" preset

When the wizard picks this:

1. Disable authoritative mode (no zones).
2. Enable hybrid resolver with recursion: true.
3. Bind to the LAN interface only.
4. Show the operator a banner: "Point your router's
   DNS at `<server-IP>` and you're done."

**Code**: just a runtime config flip — but the banner
is what makes the persona-fit explicit.

### T2.4 — "What changed?" dashboard

The existing UI shows record CRUD. Pi-hole users
expect a query-feed dashboard. Surface:

* QPS sparkline (last hour).
* Block-rate gauge (total / blocked / passthru).
* Top 10 blocked domains.
* Top 10 most-active clients.

The Prometheus metrics already feed this — just wire
a LiveView page that polls every 5 s and renders it.

**Code**: `dns_ui_web/live/dashboard_live.ex`. Make it
the landing page after login.

### T2.5 — "Disable / pause" affordance

A pi-hole user who breaks something needs a single
click to reduce their server to "transparent
forwarder" so DNS keeps working while they fix it.

* **Pause UI button**: flips a runtime flag that
  bypasses every plugin and forwards every query
  upstream.
* **5-minute / 1-hour / "until I un-pause"** options.

**Code**: a new `ExDns.PauseMode` module + UI affordance.

### T2.6 — Mobile UI verification

Run the existing LiveView pages at 375 × 667 (iPhone
SE), 390 × 844 (iPhone 13), 412 × 915 (Android).
Audit:

* Sidebar collapses to a burger.
* Tables horizontal-scroll cleanly.
* Forms readable without zoom.

**Code**: Tailwind responsive review of the existing
templates. Likely two days of polish, not a rewrite.

## Tier 3 — operator quality-of-life polish

The pi-hole user is now happy. These are the things
that make the BIND user happy and the pi-hole user
who graduates also happy.

### T3.1 — Standalone CLI (`exdns` binary)

Today's `bin/exdnsctl` shells into `mix exdns.ctl`,
requires the source tree on disk, and assumes Mix is
in `$PATH`. Pi-hole users who installed via T1.2 don't
have any of that.

* **What**: ship a single-file CLI compiled into the
  release tarball at `bin/exdns`. Connects to the
  running release via `Erlang.distribution` (or the
  release's `:rpc`) — no Mix dependency.
* **Subcommands** (covers 90% of operator needs):
  * `exdns status` — health summary.
  * `exdns zone {list, show, reload, dump}`
  * `exdns record {add, update, delete}`
  * `exdns token {issue, list, revoke}`
  * `exdns blackhole {refresh, allow, deny}`
  * `exdns pause [duration]` / `exdns unpause`
  * `exdns logs {tail, query}`
* **Acceptance**: a fresh-install pi-hole user can
  run `exdns status` in their terminal and get human-
  readable output without typing `mix`.

### T3.2 — `exdns update` self-update

Pi-hole's `pihole -up` is the killer feature for
naive operators.

* **What**: `exdns update` checks GitHub Releases for
  a newer version, downloads the matching tarball,
  drains the running instance, swaps the symlink,
  restarts.
* **Safety**: refuses to update if the new version's
  changelog has any `### Migration` heading without
  an explicit `--force` / `--migration-ack` flag.
* **Acceptance**: a pi-hole user runs `sudo exdns
  update` and is on the new version 60 seconds later.

### T3.3 — `exdns doctor`

`named-checkconf`-equivalent. Run from the CLI:

* Validates `runtime.exs` against the schema.
* Checks every loaded zone parses cleanly.
* Verifies DNSSEC keys are present + valid.
* Confirms the listener is actually bound (compare
  `ss -lnpu | grep :53` with the Application config).
* Confirms EKV quorum.
* Checks cert expiry for DoT / DoH / admin TLS.
* Warns on the obvious mistakes (apex CNAME, cycles
  in CNAME chains, unsigned glue for signed zones).

Output: clean ✅ or a numbered list of problems with
fix suggestions.

### T3.4 — Pi-hole import command

`exdns import pi-hole </path/to/pihole-config.json>`
reads a pi-hole export and creates the equivalent
ExDns BlackHole configuration: subscribed adlists,
allow / deny entries, group definitions.

Drives migration off pi-hole; explicit recognition
that we're in their lane.

### T3.5 — Documentation by persona

Add three landing pages that route to existing guides
by persona:

* **`docs/i-want/block-ads.md`** — pi-hole-shaped
  user. Links to: install, dashboard, blocklists.
* **`docs/i-want/host-a-domain.md`** — small-business.
  Links to: install, zone wizard, delegation, DNSSEC.
* **`docs/i-want/run-bind-replacement.md`** —
  experienced operator. Links to: every guide.

Existing guides stay; new pages are persona-shaped
indexes.

### T3.6 — Observability: out-of-the-box dashboard

Ship a Grafana dashboard JSON in
`contrib/grafana/exdns.json` that talks to the
already-shipped Prometheus exporter. Operators
import it and get the standard panel set without
designing one.

### T3.7 — Pre-flight DNS-leak check

A `/setup-complete` page that runs three queries
through the new server (one A, one AAAA, one TXT)
from the operator's browser, displays the answers,
and confirms reverse-resolution works. "If you saw
the right values here, your DNS server is working."

Reduces the "did I install it right?" anxiety for
pi-hole-class users.

## Done criteria — measurable bars

The work above is only worth doing if we can measure it.
Two timed user-study scenarios; both should pass before
public launch.

### Scenario A — pi-hole user, fresh Raspberry Pi

* **Profile**: a competent home user who's installed
  pi-hole before. Reads short docs, doesn't read RFCs.
* **Hardware**: a Pi 4 or equivalent ARM box with a
  clean Debian/Raspberry Pi OS image.
* **Task**: "Make this device the DNS server for your
  home network. Block ads."
* **Bar**:
  * **5 minutes** from `curl … | bash` to the UI
    showing "Ad-blocking is on for `<LAN-CIDR>`".
  * **Zero** terminal commands after the install
    line.
  * **Zero** zone files seen.
* **Failure modes that block launch**:
  * Operator can't find the install URL.
  * Installer fails on common Pi distros.
  * Wizard asks for information the operator can't
    provide.

### Scenario B — BIND operator migrating from named

* **Profile**: an SRE with `named.conf` files and a
  list of zones they currently host.
* **Hardware**: a fresh Linux VM in their existing
  infra.
* **Task**: "Replace BIND with ExDns serving the same
  zones, with DNSSEC, behind your existing
  observability stack."
* **Bar**:
  * **30 minutes** from install to first authoritative
    answer for their existing zones.
  * Their zone files load **without modification**.
  * `/metrics` Prometheus endpoint works with the
    existing scrape config.
  * `exdns doctor` reports zero issues.
* **Failure modes that block launch**:
  * Common BIND zone-file features fail to parse.
  * No CLI for everyday operations.
  * No DNSSEC pipeline that maps to the operator's
    existing rollover SOPs.

## Sequencing

| Tier | Calendar order | Blocks launch? |
|---|---|---|
| Tier 1 (T1.1–T1.5) | First. Two weeks. | **Yes.** All five mandatory before any public test deploy. |
| Tier 2 (T2.1–T2.6) | Second. Two weeks. | T2.1 (BlackHole preset), T2.2 (zone wizard), T2.4 (dashboard), T2.5 (pause) are launch blockers. T2.3 and T2.6 are stretch. |
| Tier 3 (T3.1–T3.7) | Third. Three weeks. | T3.1 (CLI) and T3.3 (doctor) are launch blockers. T3.2 (auto-update) and T3.6 (Grafana JSON) are stretch. T3.4 (pi-hole import) is post-launch. |

**Total: ~7 weeks of focused work to clear both bars.**

## Out of scope (deliberate)

Things that look like they belong here but aren't going
on this plan:

* **DHCP integration.** Pi-hole offers it; we won't.
  DHCP is a separate concern, plenty of good tools
  exist, mixing them invites bugs. We document
  pointing the existing DHCP at us.
* **Captive portal / parental controls.** Pi-hole
  bolts these on; out of scope for a DNS server.
* **GUI for everything.** Power users want config-as-
  code. We commit to keeping `runtime.exs` first-class.
  The UI is for daily ops; configuration is files.
* **Windows installer.** macOS + Linux only.

## What this plan does *not* break

Importantly, none of the Tier 1–3 work changes the
existing capabilities or operator workflows. A user
who installed via the source path today continues to
have everything they have. The new affordances are
**additive**.

* `runtime.exs` stays as the source of truth.
* The HTTP API is unchanged.
* Existing guides + runbooks stay in place.
* CLI gains, never loses, subcommands.

The pi-hole-shaped on-ramp is built **on top of** the
BIND-grade core, not in place of it.

## Open questions

These aren't blockers for the plan but need answers
before specific items ship:

1. **Where does the install script live?** Stable URL
   or just `curl github.com/...`? GitHub direct is
   fine for v0; a vanity domain comes later.
2. **What's the curated default blocklist?** Steven
   Black is the obvious choice, but politically we
   should probably ship "operator-must-pick" with a
   suggested list rather than imply endorsement.
3. **Bootstrap-code transport.** File on disk
   (`/root/exdns-bootstrap.txt`) is simplest but only
   works for ssh-able hosts. Phone-only operators
   need an alternate (printed in the systemd journal?
   QR code generated locally?).
4. **How aggressive should `exdns doctor` be?** Strict
   mode (every CNAME-coexistence violation fails) vs
   advisory mode (warns but exits 0). Probably both,
   with `--strict`.

These are decisions to make as the work lands; flagging
here so they don't get lost.

