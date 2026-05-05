defmodule ExDns.Zone.Catalog.Applier do
  @moduledoc """
  Reconciles a parsed catalog against the running set of
  `ExDns.Zone.Secondary` state machines.

  Members listed in the catalog but not currently being served
  start fresh secondaries. Secondaries running for members no
  longer in the catalog are stopped and their zones unloaded. The
  primary list, TSIG key, and SOA-timer defaults all flow in from
  the catalog subscription's config.

  ## Wiring

  Operators feed this from one of two places:

  * The `ExDns.Zone.Catalog.Subscription` GenServer (a follow-up
    that polls a primary's catalog zone and re-applies on serial
    change).

  * A one-shot loader (parse a static catalog file at startup,
    apply once). Useful for deployments that maintain the catalog
    out-of-band but still want catalog semantics in their config.

  Either way, this module owns the side effect of
  starting/stopping secondaries and unloading zones.
  """

  alias ExDns.Storage
  alias ExDns.Zone.Catalog.Member
  alias ExDns.Zone.Secondary

  require Logger

  @doc """
  Reconcile `members` against the currently-running secondary
  zones.

  ### Arguments

  * `members` is a list of `%Catalog.Member{}` from
    `Catalog.parse/2`.

  * `defaults` is a keyword list providing the per-member
    Secondary config that the catalog itself doesn't carry:

  ### Options

  * `:primaries` — list of `{ip, port}` tuples (required).
  * `:tsig_key` — TSIG key name (optional).
  * `:initial_refresh_seconds`, `:initial_retry_seconds`,
    `:initial_expire_seconds` — passed straight through.

  ### Returns

  * `%{started: [name], stopped: [name]}`.
  """
  @spec apply([Member.t()], keyword()) :: %{started: [binary()], stopped: [binary()]}
  def apply(members, defaults \\ []) when is_list(members) do
    desired = MapSet.new(members, & &1.name)
    running = MapSet.new(running_secondaries())

    to_start = MapSet.difference(desired, running) |> MapSet.to_list()
    to_stop = MapSet.difference(running, desired) |> MapSet.to_list()

    Enum.each(to_start, &start_member(&1, members, defaults))
    Enum.each(to_stop, &stop_member/1)

    :telemetry.execute(
      [:ex_dns, :catalog, :reconcile],
      %{started: length(to_start), stopped: length(to_stop)},
      %{members: MapSet.size(desired)}
    )

    %{started: to_start, stopped: to_stop}
  end

  # ----- internals -------------------------------------------------

  defp start_member(name, members, defaults) do
    member = Enum.find(members, &(&1.name == name))

    primaries = Keyword.fetch!(defaults, :primaries)

    config =
      defaults
      |> Keyword.take([:tsig_key, :initial_refresh_seconds, :initial_retry_seconds, :initial_expire_seconds])
      |> Map.new()
      |> Map.merge(%{
        apex: name,
        primaries: member_primaries(member, primaries)
      })

    case Secondary.start_link(config) do
      {:ok, _pid} ->
        Logger.info("ExDns.Zone.Catalog.Applier: started secondary for #{name}")
        :ok

      {:error, {:already_started, _pid}} ->
        :ok

      {:error, reason} ->
        Logger.error(
          "ExDns.Zone.Catalog.Applier: failed to start secondary for #{name}: #{inspect(reason)}"
        )

        :ok
    end
  end

  defp stop_member(name) do
    case Process.whereis(secondary_name(name)) do
      nil ->
        :ok

      pid ->
        Logger.info("ExDns.Zone.Catalog.Applier: stopping secondary for #{name}")
        :gen_statem.stop(pid, :normal, 5_000)
        Storage.delete_zone(name)
    end
  end

  # When the catalog member specifies a `coo` (Change of Ownership)
  # property pointing at a different primary, prefer that — RFC
  # 9432 §6.1. Otherwise use the catalog-wide primary list.
  defp member_primaries(%Member{coo: nil}, defaults), do: defaults

  defp member_primaries(%Member{coo: _coo}, defaults) do
    # COO indicates the zone has moved primaries; ExDns doesn't yet
    # resolve the COO target's address, so we still send queries
    # to the catalog-wide primary list. Logging here so an
    # operator notices the gap; this is the natural place to hook
    # COO-aware primary discovery in a follow-up.
    Logger.info("ExDns.Zone.Catalog.Applier: COO property present, using catalog primaries (COO not yet honoured)")
    defaults
  end

  defp running_secondaries do
    # Walk the registered process names looking for the
    # Secondary's per-zone naming convention.
    prefix = "Elixir.ExDns.Zone.Secondary."

    for name <- Process.registered(),
        name_str = Atom.to_string(name),
        String.starts_with?(name_str, prefix) do
      String.replace_prefix(name_str, prefix, "") |> String.downcase()
    end
  end

  defp secondary_name(apex) do
    Module.concat(ExDns.Zone.Secondary, normalise(apex))
  end

  defp normalise(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end
end
