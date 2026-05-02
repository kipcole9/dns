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
      docs: docs(),
      dialyzer: [
        plt_add_apps: [:mix, :ex_unit]
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
      {:ex_doc, "~> 0.34", only: [:dev], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
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
