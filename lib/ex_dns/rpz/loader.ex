defmodule ExDns.RPZ.Loader do
  @moduledoc """
  Read RPZ zone files from disk, parse them, install the
  resulting rule set into `ExDns.RPZ.Store`.

  Operators point this at one or more files (or globs) via
  `:ex_dns, :rpz, [zones: ["..."]]` and call `load_all/0` at
  startup or whenever the on-disk content changes (HTTP
  reload, signal handler, periodic poll).

  ## Multi-zone semantics

  Rules from every file concatenate in source order. The
  matcher's first-match-wins rule means file ordering matters
  — list narrower / higher-priority RPZs first.

  ## Example

      config :ex_dns, :rpz,
        enabled: true,
        zones: [
          "/etc/exdns/rpz/local-allowlist.zone",
          "/etc/exdns/rpz/blocklist.zone"
        ]
  """

  alias ExDns.RPZ
  alias ExDns.RPZ.Store
  alias ExDns.Zone

  require Logger

  @doc """
  Read every configured RPZ zone, parse + concatenate the rule
  sets, install into `Store`.

  ### Returns

  * `{:ok, rule_count}` on success.
  * `{:ok, 0}` when no `:zones` are configured (no-op,
    documented).
  """
  @spec load_all() :: {:ok, non_neg_integer()}
  def load_all do
    paths =
      Application.get_env(:ex_dns, :rpz, [])
      |> Keyword.get(:zones, [])
      |> ExDns.Zone.Source.expand()

    rules =
      Enum.flat_map(paths, fn path ->
        case Zone.load_file(path) do
          {:ok, %Zone{} = zone} ->
            apex = Zone.name(zone)
            parsed = RPZ.parse(apex, zone.resources)
            Logger.info("ExDns.RPZ.Loader: loaded #{length(parsed)} rule(s) from #{path}")
            parsed

          {:error, reason} ->
            Logger.error("ExDns.RPZ.Loader: failed to load #{path}: #{inspect(reason)}")
            []
        end
      end)

    Store.put(rules)
    {:ok, length(rules)}
  end
end
