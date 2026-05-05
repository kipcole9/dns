import Config

# Bench environment uses dev-equivalent settings — local listener,
# no clustering, no recursion. Benchee benchmarks live under
# `bench/` and are run with `MIX_ENV=bench mix run bench/<name>.exs`.
config :ex_dns,
  listener_port: 8000
