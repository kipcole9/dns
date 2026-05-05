defmodule ExDns.Zone.Reload do
  @moduledoc """
  Reload zones at runtime without restarting the application.

  Re-reads the files listed in `:ex_dns, :zones` and re-loads each
  one through `ExDns.Storage.put_zone/2`. Because put_zone goes
  through the normal storage path, the reload also fires:

  * IXFR journal entries (when the SOA serial advances), and
  * outbound NOTIFYs to configured secondaries.

  ## Triggers

  * `reload_all/0` — re-read every configured zone file.
  * `reload_path/1` — re-read a single zone file.

  Operators typically wire one of these to a SIGHUP handler, an
  admin HTTP endpoint, or a `:rpc.call/4` from a control script.

  ## Failure semantics

  A failed reload of one zone does not abort the others — it logs
  and continues. The previously-loaded copy of any zone whose new
  file fails to parse stays in place; reload is best-effort and
  never leaves the server in a state worse than before.
  """

  require Logger

  @doc """
  Reload every zone listed in the `:ex_dns, :zones` config.

  ### Returns

  * `{loaded, failed}` — counts of successfully reloaded zones
    and zones that failed to reload.

  ### Examples

      iex> {_loaded, _failed} = ExDns.Zone.Reload.reload_all()

  """
  @spec reload_all() :: {non_neg_integer(), non_neg_integer()}
  def reload_all do
    zones =
      Application.get_env(:ex_dns, :zones, [])
      |> ExDns.Zone.Source.expand()

    {loaded, failed} =
      Enum.reduce(zones, {0, 0}, fn path, {ok, err} ->
        case reload_path(path) do
          :ok -> {ok + 1, err}
          {:error, _} -> {ok, err + 1}
        end
      end)

    Logger.info("ExDns.Zone.Reload: reloaded #{loaded} zones (#{failed} failures)")

    :telemetry.execute(
      [:ex_dns, :zone, :reload, :stop],
      %{loaded: loaded, failed: failed},
      %{}
    )

    {loaded, failed}
  end

  @doc """
  Reload a single zone from `path`. The apex is taken from the
  zone file's SOA, so callers don't have to specify it.

  ### Arguments

  * `path` is the filesystem path of the zone file.

  ### Returns

  * `:ok` on success.
  * `{:error, reason}` when the file cannot be read or parsed.
  """
  @spec reload_path(Path.t()) :: :ok | {:error, term()}
  def reload_path(path) when is_binary(path) do
    case ExDns.Zone.load_file(path) do
      {:ok, zone} ->
        Logger.info("ExDns.Zone.Reload: loaded #{ExDns.Zone.name(zone)} from #{path}")
        :ok

      {:error, reason} = err ->
        Logger.error("ExDns.Zone.Reload: failed to load #{path}: #{inspect(reason)}")
        err
    end
  end

end
