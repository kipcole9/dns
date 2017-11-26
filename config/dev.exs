use Mix.Config

config :ex_dns,
  resolver: ExDns.Resolver.Default,
  storage: ExDns.Storage.ETS,
  resolver_pool_size: 5,
  resolver_pool_overflow_size: 1,
  listener_port: 8000

config :prometheus, ExDns.Prometheus.Exporter,
  path: "/metrics",
  format: :auto, ## or :protobuf, or :text
  registry: :default,
  auth: false
