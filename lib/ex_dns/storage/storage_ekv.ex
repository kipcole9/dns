defmodule ExDns.Storage.EKV do
  @moduledoc """
  EKV-backed zone storage with an ETS hot-path cache.

  ## Why this shape

  Authoritative-server query latency is dominated by the
  per-RRset lookup. EKV is great for cluster-replicated
  durable state but adds latency on the hot path. The
  pragmatic split is:

  * **Reads**: served entirely from the existing
    `ExDns.Storage.ETS` tables — no EKV round-trip on the
    query path.

  * **Writes (`put_zone/2`, `delete_zone/1`)**: write through
    to ETS first (so the hot path sees the change
    immediately + the journal/NOTIFY side-effects fire),
    then mirror the canonical record list into EKV under
    `zone/<apex>/records`. EKV's replication propagates the
    change to other cluster members.

  * **Bootstrap**: on `init/0`, after the ETS tables exist,
    hydrate them from EKV so a fresh node picks up
    cluster-known zones before serving queries.

  ## Layout

      zone/<apex>/records  ->  [record :: struct(), ...]

  ## Cluster propagation note

  Today the adapter writes through but does not subscribe
  to EKV change notifications. That covers single-node
  durability and gives clusters the same write-side
  propagation. Auto-applying remote-origin writes to local
  ETS is an enhancement tracked in
  `plans/2026-05-06-server-clustering-via-ekv.md`.
  """

  @behaviour ExDns.Storage

  alias ExDns.EKV
  alias ExDns.Storage.ETS, as: ETSStore

  @prefix "zone/"
  @suffix "/records"

  @impl true
  def init do
    fresh_table? = :ets.whereis(:ex_dns_zones) == :undefined
    :ok = ETSStore.init()

    # Hydrate when the ETS index table didn't exist before
    # this `init/0` — that covers fresh boots and
    # application restarts in tests. After that, all writes
    # go through `put_zone/2` so ETS and EKV stay in sync.
    if fresh_table?, do: hydrate(), else: :ok
  end

  defp hydrate do
    @prefix
    |> EKV.scan()
    |> Enum.each(fn entry ->
      {key, records, _meta} = unpack(entry)

      case strip(key) do
        {:ok, apex} when is_list(records) ->
          # Use the underlying adapter directly: we don't
          # want this hydrate write to mirror back to EKV
          # (it's already there) or to fire NOTIFY.
          ETSStore.put_zone(apex, records)

        _ ->
          :ok
      end
    end)

    :ok
  end

  @impl true
  def put_zone(apex, records) when is_binary(apex) and is_list(records) do
    :ok = ETSStore.put_zone(apex, records)
    :ok = EKV.put(zone_key(apex), records)
    :ok
  end

  @impl true
  def delete_zone(apex) when is_binary(apex) do
    :ok = ETSStore.delete_zone(apex)
    EKV.delete(zone_key(apex))
    :ok
  end

  @impl true
  def zones, do: ETSStore.zones()

  @impl true
  def find_zone(qname), do: ETSStore.find_zone(qname)

  @impl true
  def lookup(qname, qtype), do: ETSStore.lookup(qname, qtype)

  @impl true
  def lookup(apex, qname, qtype), do: ETSStore.lookup(apex, qname, qtype)

  @impl true
  def lookup_any(qname), do: ETSStore.lookup_any(qname)

  @impl true
  def lookup_any(apex, qname), do: ETSStore.lookup_any(apex, qname)

  @impl true
  def lookup_wildcard(qname, qtype), do: ETSStore.lookup_wildcard(qname, qtype)

  @impl true
  def wildcard_name_exists?(qname), do: ETSStore.wildcard_name_exists?(qname)

  @impl true
  def find_delegation(qname), do: ETSStore.find_delegation(qname)

  @impl true
  def dump_zone(apex), do: ETSStore.dump_zone(apex)

  # ----- helpers ----------------------------------------------------

  defp zone_key(apex) do
    @prefix <> normalize(apex) <> @suffix
  end

  defp strip(@prefix <> rest) do
    case String.split(rest, @suffix, trim: false) do
      [apex, ""] -> {:ok, apex}
      _ -> :error
    end
  end

  defp strip(_), do: :error

  defp unpack({key, value, meta}), do: {key, value, meta}
  defp unpack({key, value}), do: {key, value, nil}

  defp normalize(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end
end
