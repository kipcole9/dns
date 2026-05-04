defmodule ExDns.Zone.Journal.Storage.ETS do
  @moduledoc """
  In-memory ETS backend for the IXFR journal. Default.

  Trade-off: zero I/O cost, lost on process exit. Suitable for
  single-node deployments that can tolerate secondaries
  re-AXFRing after a restart.
  """

  @behaviour ExDns.Zone.Journal.Storage

  @table :ex_dns_zone_journal

  @impl true
  def init(_options) do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [
          :ordered_set,
          :named_table,
          :public,
          read_concurrency: true,
          write_concurrency: true
        ])

      _ ->
        @table
    end

    @table
  end

  @impl true
  def clear do
    init([])

    try do
      :ets.delete_all_objects(@table)
    rescue
      ArgumentError -> :ok
    end

    :ok
  end

  @impl true
  def insert(apex, serial, entry) do
    init([])
    :ets.insert(@table, {{apex, serial}, entry})
    :ok
  end

  @impl true
  def entries(apex) do
    init([])

    @table
    |> :ets.match_object({{apex, :"$1"}, :"$2"})
    |> Enum.map(fn {{_, _serial}, entry} -> entry end)
  end
end
