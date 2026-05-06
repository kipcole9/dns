defmodule ExDns.Mixfile do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/kipcole9/dns"

  def project do
    [
      app: :ex_dns,
      version: @version,
      elixir: "~> 1.17",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      compilers: [:leex, :yecc] ++ Mix.compilers(),
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      source_url: @source_url,
      description: description(),
      package: package(),
      docs: docs(),
      releases: releases(),
      dialyzer: [
        plt_add_apps: [:mix, :ex_unit]
      ]
    ]
  end

  defp description do
    "Elixir-native DNS server. Authoritative + recursive in one binary, " <>
      "with DNSSEC, dynamic UPDATE, AXFR/IXFR/NOTIFY, DoT/DoH, an HTTP " <>
      "operator API, a CIDR-routed plugin framework, and EKV-backed " <>
      "cluster replication."
  end

  defp package do
    [
      maintainers: ["Kip Cole"],
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md",
        "Guides" => "#{@source_url}/tree/main/guides"
      },
      files: [
        "lib",
        "src",
        "priv/openapi",
        "config/config.exs",
        "config/prod.exs",
        "config/runtime.exs.example",
        "contrib/systemd",
        "guides",
        "mix.exs",
        "README.md",
        "CHANGELOG.md",
        "LICENSE"
      ]
    ]
  end

  # `mix release` builds a self-contained tarball under
  # `_build/<env>/rel/ex_dns/`. Operators run it via
  # `bin/ex_dns start` (foreground) or `bin/ex_dns daemon`
  # (background); the included Erlang VM means the host
  # doesn't need Elixir / Erlang installed.
  defp releases do
    [
      ex_dns: [
        include_executables_for: [:unix],
        applications: [
          runtime_tools: :permanent,
          ex_dns: :permanent
        ],
        steps: [:assemble, :tar],
        # `cookie` is regenerated each build by default —
        # fine for single-node, but multi-node clusters need
        # the same cookie on every host. Operators set this
        # via `RELEASE_COOKIE` at runtime; the file-based
        # default is overridden when the env var is set.
        cookie: "ex_dns"
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {ExDns.Application, []}
    ]
  end

  defp deps do
    [
      {:poolboy, "~> 1.5"},
      {:idna, "~> 6.1"},
      {:mime, "~> 2.0"},
      {:thousand_island, "~> 1.3"},
      {:bandit, "~> 1.6"},
      {:plug, "~> 1.16"},
      {:libcluster, "~> 3.4", optional: true},
      {:telemetry, "~> 1.3"},
      {:telemetry_metrics, "~> 1.0"},
      {:telemetry_metrics_prometheus, "~> 1.1"},
      {:opentelemetry_api, "~> 1.4", optional: true},
      {:ex_doc, "~> 0.34", only: [:dev], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:stream_data, "~> 1.1", only: [:dev, :test], runtime: false},
      {:benchee, "~> 1.3", only: :bench, runtime: false},
      {:ekv, "~> 0.4"},
      {:exqlite, "~> 0.27", optional: true},
      {:req, "~> 0.5", optional: true}
    ] ++ maybe_json_polyfill()
  end

  # OTP 27 ships a built-in `:json` module. On older OTPs we
  # depend on `:json_polyfill`, which provides a compatible API
  # backed by Jason. Detection happens at compile time of mix.exs
  # itself, so the build produces the right dep graph for the host
  # OTP.
  defp maybe_json_polyfill do
    if Code.ensure_loaded?(:json) do
      []
    else
      [{:json_polyfill, "~> 0.2 or ~> 1.0"}]
    end
  end

  defp elixirc_paths(:test), do: ["lib", "mix", "test", "test/support"]
  defp elixirc_paths(:dev), do: ["lib", "mix"]
  defp elixirc_paths(_), do: ["lib"]

  defp docs do
    [
      main: "ExDns",
      source_url: @source_url,
      extras: ["README.md"]
    ]
  end
end
