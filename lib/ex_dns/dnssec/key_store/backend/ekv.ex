defmodule ExDns.DNSSEC.KeyStore.Backend.EKV do
  @moduledoc """
  EKV-backed DNSSEC key store. Cluster-replicated when EKV
  runs in cluster mode; identical code path single-node.

  ## Layout

  One key per zone:

      dnssec/<zone> -> [entry, entry, ...]

  Each entry is `%{dnskey: …, private_key: …, state: …}`.
  Operations replace the entire per-zone list — there are
  rarely more than a handful of keys per zone, so the
  read-modify-write cost is negligible.
  """

  @behaviour ExDns.DNSSEC.KeyStore.Backend

  alias ExDns.EKV

  @prefix "dnssec/"

  @impl true
  def init, do: :ok

  @impl true
  def list(zone) when is_binary(zone) do
    EKV.lookup(key(zone)) || []
  end

  @impl true
  def put_list(zone, entries) when is_binary(zone) and is_list(entries) do
    :ok = EKV.put(key(zone), entries)
    :ok
  end

  @impl true
  def delete_zone(zone) when is_binary(zone) do
    EKV.delete(key(zone))
    :ok
  end

  @impl true
  def all_zones do
    @prefix
    |> EKV.scan()
    |> Enum.map(fn
      {key, _value, _meta} -> strip_prefix(key)
      {key, _value} -> strip_prefix(key)
    end)
  end

  @impl true
  def clear do
    Enum.each(all_zones(), &delete_zone/1)
    :ok
  end

  defp key(zone), do: @prefix <> zone

  defp strip_prefix(@prefix <> zone), do: zone
end
