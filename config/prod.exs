import Config

# Compile-time defaults for `MIX_ENV=prod`. Per-deployment
# settings (zones, NSID identifier, EKV cluster size,
# blocklist URLs, TLS certs, etc) live in
# `config/runtime.exs`, which is evaluated at boot from
# the release tarball. Use `config/runtime.exs.example`
# as the starting point.

# Reasonable production defaults. Override in runtime.exs.
config :ex_dns,
  resolver: ExDns.Resolver.Default,
  storage: ExDns.Storage.EKV
