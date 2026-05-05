defmodule ExDns.DNSSEC.KeyStore.Backend.ETS do
  @moduledoc """
  In-process ETS-backed DNSSEC key store. Per-node only —
  use the EKV backend for cluster-replicated key state.
  """

  @behaviour ExDns.DNSSEC.KeyStore.Backend

  @table :ex_dns_dnssec_keys

  @impl true
  def init do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [:set, :public, :named_table, read_concurrency: true])
        :ok

      _ ->
        :ok
    end
  end

  @impl true
  def list(zone) when is_binary(zone) do
    init()

    case :ets.lookup(@table, zone) do
      [{^zone, entries}] -> entries
      [] -> []
    end
  end

  @impl true
  def put_list(zone, entries) when is_binary(zone) and is_list(entries) do
    init()
    :ets.insert(@table, {zone, entries})
    :ok
  end

  @impl true
  def delete_zone(zone) when is_binary(zone) do
    init()
    :ets.delete(@table, zone)
    :ok
  end

  @impl true
  def all_zones do
    init()
    :ets.foldl(fn {zone, _entries}, acc -> [zone | acc] end, [], @table)
  end

  @impl true
  def clear do
    init()

    try do
      :ets.delete_all_objects(@table)
    rescue
      ArgumentError -> :ok
    end

    :ok
  end
end
