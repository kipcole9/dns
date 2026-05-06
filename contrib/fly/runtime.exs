###############################################################################
# Fly.io runtime config for ExDns — single-node test deployment.
#
# Baked into the Docker image at /opt/exdns/etc/runtime.exs and pointed at
# via EXDNS_RUNTIME_CONFIG. Variable values are sourced from Fly secrets:
#
#   fly secrets set EXDNS_PUBLIC_NS=ns1.elixir-dns-test.com
#   fly secrets set EXDNS_NSID=exdns-test-fly-lhr
#   fly secrets set RELEASE_COOKIE=<openssl rand -hex 32>
###############################################################################

import Config

# ----- Listener bindings ----------------------------------------------------

# Bind on all interfaces — Fly's networking layer delivers public traffic
# to 0.0.0.0:53 on the dedicated v4.
config :ex_dns,
  listener_port: 53,
  zones: ["/etc/exdns/zones.d/*.zone"]

# ----- Server identity (RFC 5001 NSID) --------------------------------------

# Echoes back our identifier when a client asks for NSID. Useful in `dig`
# output for confirming "yes, this answer came from MY server".
config :ex_dns, :nsid,
  enabled: true,
  identifier: System.get_env("EXDNS_NSID", "exdns")

# ----- EKV (storage substrate) ----------------------------------------------

# Single-node EKV. Volume-backed; survives machine restart.
# Multi-node clustering is a graduation step (see plans/fly_io_initial_deploy.md §9).
config :ex_dns, :ekv,
  enabled: true,
  data_dir: "/var/lib/exdns/ekv",
  cluster_size: 1,
  mode: :member

# ----- Persistent zone snapshot ---------------------------------------------

# Belt-and-braces backup for runtime mutations (RFC 2136 UPDATE, AXFR
# secondary feeds, catalog applies). EKV already persists this state;
# the snapshot is a parallel copy that's easier to ship off-host.
config :ex_dns, :zone_snapshot,
  enabled: true,
  path: "/var/lib/exdns/snapshot.bin"

# ----- Admin HTTP API -------------------------------------------------------

# Loopback only — reach via `fly ssh console -C "/opt/exdns/bin/exdnsctl …"`.
# NEVER bind this to 0.0.0.0 on a public Fly machine.
config :ex_dns, :api,
  enabled: true,
  port: 9571,
  bind: {127, 0, 0, 1},
  token_path: "/var/lib/exdns/tokens.json"

# ----- Health probe ---------------------------------------------------------

# Fly's TCP health check hits this port. Loopback-only on the machine
# (Fly probes from inside the firewall).
config :ex_dns, :health,
  enabled: true,
  port: 9572

# ----- Prometheus metrics ---------------------------------------------------

# Internal scrape only. Fly's own Grafana picks this up via the machine's
# private 6PN address; external scrape requires an SSH tunnel or a
# private network peering.
config :ex_dns, :metrics,
  enabled: true,
  port: 9573

# ----- Abuse mitigation (T1.6 / T1.7 / T2.3 defaults made explicit) ---------

# RRL token bucket per (subnet, qname, qtype, response_kind).
config :ex_dns, :rrl,
  enabled: true,
  responses_per_second: 5,
  burst: 25,
  slip: 2,
  ipv4_prefix: 24,
  ipv6_prefix: 56

# DNS Cookies (RFC 7873). `:enforce` stays off until we observe cookie
# adoption in real traffic; turn on later to reject spoofed clients with
# BADCOOKIE.
config :ex_dns, :cookies,
  enabled: true,
  enforce: false

# Per-IP API auth-failure throttle (T1.5).
config :ex_dns, :api_auth_throttle,
  enabled: true,
  burst: 10,
  refill_seconds: 60,
  cooldown_seconds: 300

# Per-source-IP concurrent connection cap for the TCP listener (T2.3).
config :ex_dns, :per_ip_cap,
  enabled: true,
  max_per_ip: 64

# Recursor cache cap (T1.7) — defends against random-subdomain water torture.
config :ex_dns, :recursor_cache,
  max_entries: 100_000

# ----- Resolver mode --------------------------------------------------------

# Authoritative-only. Recursion is intentionally OFF for this iteration:
# we serve answers for elixir-dns-test.com and refuse everything else
# rather than become an open recursor on the public internet.
config :ex_dns, recursion: false

# ----- DNSSEC ---------------------------------------------------------------

# DNSSEC signing comes in graduation step 2. The validator's fix from
# T1.1 (RRSIG inception/expiration enforcement) applies regardless;
# AlgorithmPolicy strict mode stays off for compatibility.
config :ex_dns, :dnssec_algorithm_policy, strict: false
