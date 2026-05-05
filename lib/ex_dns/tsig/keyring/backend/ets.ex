defmodule ExDns.TSIG.Keyring.Backend.ETS do
  @moduledoc """
  In-process ETS-backed runtime keyring. Per-node only —
  use the EKV backend for cluster-replicated runtime keys.
  """

  @behaviour ExDns.TSIG.Keyring.Backend

  @table :ex_dns_tsig_keys

  @impl true
  def init do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [
          :set,
          :public,
          :named_table,
          read_concurrency: true,
          write_concurrency: true
        ])

      _ ->
        :ok
    end

    :ok
  end

  @impl true
  def lookup(name) when is_binary(name) do
    init()

    case :ets.lookup(@table, name) do
      [{^name, value}] -> {:ok, value}
      [] -> :error
    end
  end

  @impl true
  def put(name, %{} = entry) when is_binary(name) do
    init()
    :ets.insert(@table, {name, entry})
    :ok
  end

  @impl true
  def delete(name) when is_binary(name) do
    init()
    :ets.delete(@table, name)
    :ok
  end

  @impl true
  def all do
    init()
    :ets.tab2list(@table)
  end
end
