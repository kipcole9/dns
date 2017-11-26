defmodule ExDns.Mixfile do
  use Mix.Project

  def project do
    [
       app: :ex_dns,
       version: "0.1.0",
       elixir: "~> 1.4",
       build_embedded: Mix.env == :prod,
       start_permanent: Mix.env == :prod,
       deps: deps(),
       elixirc_paths: elixirc_paths(Mix.env)
   ]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [
       extra_applications: [:logger, :prometheus_ex],
       mod: {ExDns.Application, []}
    ]
  end

  defp deps do
    [
      {:poolboy, "~> 1.5"},
      {:cowboy, "~> 1.0"},
      {:plug, "~> 1.0"},
      {:idna, "~> 5.0"}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "mix", "test", "test/support"]
  defp elixirc_paths(:dev),  do: ["lib", "mix"]
  defp elixirc_paths(_),     do: ["lib"]
end
