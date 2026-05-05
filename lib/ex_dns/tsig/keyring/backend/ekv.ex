defmodule ExDns.TSIG.Keyring.Backend.EKV do
  @moduledoc """
  EKV-backed runtime TSIG keyring. Cluster-replicated when
  EKV is configured for multiple members; works identically
  on a single node.

  ## Layout

  Single key `tsig/keys` holds a `%{name => entry}` map.
  Per-key reads (`lookup/1`) load the whole map and pull
  one entry — fine because the map is small (~tens of keys
  in practice).
  """

  @behaviour ExDns.TSIG.Keyring.Backend

  alias ExDns.EKV

  @key "tsig/keys"

  @impl true
  def init, do: :ok

  @impl true
  def lookup(name) when is_binary(name) do
    case EKV.lookup(@key) || %{} do
      %{^name => entry} -> {:ok, entry}
      _ -> :error
    end
  end

  @impl true
  def put(name, %{} = entry) when is_binary(name) do
    new_map = Map.put(EKV.lookup(@key) || %{}, name, entry)
    :ok = EKV.put(@key, new_map)
    :ok
  end

  @impl true
  def delete(name) when is_binary(name) do
    new_map = Map.delete(EKV.lookup(@key) || %{}, name)
    :ok = EKV.put(@key, new_map)
    :ok
  end

  @impl true
  def all do
    (EKV.lookup(@key) || %{}) |> Map.to_list()
  end
end
