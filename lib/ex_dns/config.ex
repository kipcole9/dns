defmodule ExDns.Config do
  @moduledoc """
  Load operator configuration from an Elixir-data file.

  Operators want a single declarative file they can put under
  config management (`/etc/exdns/exdns.conf`) rather than
  scattered `Application.put_env` calls inside `runtime.exs`.
  This module loads such a file and applies its contents to the
  running application.

  ## File format

  The file evaluates to a single keyword list. Each entry maps
  an `:ex_dns` configuration key to its value:

      # /etc/exdns/exdns.conf
      [
        listener_port: 53,

        zones: [
          "/etc/exdns/zones/*.zone"
        ],

        refuse_any: true,

        nsid: [enabled: true, identifier: "ns1.example.com"],

        rrl: [enabled: true, responses_per_second: 5, burst: 25],

        views: [
          %{
            name: "internal",
            match: [{:cidr, {{10, 0, 0, 0}, 8}}],
            zones: []
          },
          %{name: "external", match: [:any], zones: []}
        ],

        transfer_acls: %{
          "example.com" => %{
            allow_cidrs: [{{10, 0, 0, 0}, 24}],
            require_tsig_key: "secondary-key"
          }
        }
      ]

  Any key valid in `config :ex_dns, key: value` works here.

  ## Why Elixir data instead of TOML / HCL

  Two reasons:

  1. **No new parser**. The format is just Elixir terms — every
     existing tuple-based config (CIDRs, TSIG keys, view match
     clauses) is expressible without translation.

  2. **No new dependency**. `Code.eval_file/1` is in stdlib;
     pulling in `:toml`, `:yaml_elixir`, etc. would add
     supply-chain surface for marginal expressivity gain.

  The trade-off is that a malformed config file raises rather
  than reports a structured parse error, but the loader catches
  every Elixir-side exception and surfaces it as
  `{:error, exception}` with the line number.

  ## Wiring

  Configure a path via the `:config_file` env var or
  `:ex_dns, :config_file, "/path/to/exdns.conf"`. When set,
  `Application.start/2` calls `load_if_configured/0` early so
  the file's settings land before any subsystem reads them.

      EXDNS_CONFIG=/etc/exdns/exdns.conf bin/exdnsctl status
  """

  require Logger

  @doc """
  Load + apply config from `path`.

  ### Arguments

  * `path` is the absolute path to the config file.

  ### Returns

  * `{:ok, applied_keys}` on success — list of keys that were
    written to `Application.put_env`.
  * `{:error, reason}` when the file can't be read or evaluated.

  ### Examples

      iex> ExDns.Config.load("/nonexistent/path")
      {:error, :enoent}

  """
  @spec load(Path.t()) :: {:ok, [atom()]} | {:error, term()}
  def load(path) when is_binary(path) do
    with {:ok, contents} <- File.read(path),
         {:ok, terms} <- evaluate(contents, path) do
      apply_terms(terms)
    end
  end

  @doc """
  Same as `load/1` but raises on any failure. Useful from
  startup hooks where a bad config should hard-fail.
  """
  @spec load!(Path.t()) :: [atom()]
  def load!(path) do
    case load(path) do
      {:ok, keys} -> keys
      {:error, reason} -> raise "ExDns.Config.load!: #{inspect(reason)}"
    end
  end

  @doc """
  Look for a config file in the standard locations and load it
  if found:

  1. `EXDNS_CONFIG` env var
  2. `:ex_dns, :config_file` application env

  Returns `:ok` either way — operators who don't use this
  feature pay no penalty.
  """
  @spec load_if_configured() :: :ok
  def load_if_configured do
    case configured_path() do
      nil ->
        :ok

      path ->
        case load(path) do
          {:ok, keys} ->
            Logger.info("ExDns.Config: loaded #{length(keys)} setting(s) from #{path}")
            :ok

          {:error, reason} ->
            Logger.error("ExDns.Config: failed to load #{path}: #{inspect(reason)}")
            :ok
        end
    end
  end

  # ----- internals --------------------------------------------------

  defp configured_path do
    System.get_env("EXDNS_CONFIG") ||
      Application.get_env(:ex_dns, :config_file)
  end

  defp evaluate(contents, path) do
    {result, _bindings} = Code.eval_string(contents, [], file: path, line: 1)
    {:ok, result}
  rescue
    error ->
      {:error, {:eval_failed, Exception.message(error)}}
  end

  defp apply_terms(terms) when is_list(terms) do
    if Keyword.keyword?(terms) do
      keys = Keyword.keys(terms)
      Enum.each(terms, fn {key, value} -> Application.put_env(:ex_dns, key, value) end)
      {:ok, keys}
    else
      {:error, :not_a_keyword_list}
    end
  end

  defp apply_terms(_), do: {:error, :not_a_keyword_list}
end
