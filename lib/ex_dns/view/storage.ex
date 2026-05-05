defmodule ExDns.View.Storage do
  @moduledoc """
  Per-view zone storage — isolates each view's zone data so the
  same apex (`example.com`) can carry different records in
  different views.

  Each view has its own ETS table (`{view_name, apex} → table_id`),
  reusing the same per-zone table layout that
  `ExDns.Storage.ETS` uses. View tables are independent — a write
  to view `A` doesn't touch view `B`'s copy of the same apex.

  ## Lookup precedence

  When the resolver has selected a view for a request, it
  consults the view's storage first. On miss (apex not present
  in the view), the resolver may either:

  * **Strict mode** — return REFUSED / NXDOMAIN at the view
    boundary. Used when each view is its own self-contained
    universe of zones.

  * **Inherit mode** — fall through to the global
    `ExDns.Storage` for any apex the view doesn't define.
    Used when views are deltas on top of a shared baseline.

  This module just stores; the resolver picks the policy.

  ## Why a separate module

  Threading a `view_name` parameter through every `Storage`
  call site would touch the entire resolver. By keeping
  view-aware storage as its own surface, the resolver only
  needs to know "do I have a view?" — yes/no — and pick which
  storage to consult. The two storages share the per-zone
  table layout so any zone-walk logic in `ExDns.Storage.ETS`
  ports straight across.
  """

  @index_table :ex_dns_view_index

  @doc """
  Initialise the view-storage index. Idempotent. Called by
  `put_zone/3` lazily so callers don't need to remember.

  ### Returns

  * `:ok`.
  """
  @spec init() :: :ok
  def init do
    case :ets.whereis(@index_table) do
      :undefined ->
        :ets.new(@index_table, [
          :set,
          :named_table,
          :public,
          read_concurrency: true,
          write_concurrency: true
        ])

      _ ->
        :ok
    end

    :ok
  end

  @doc """
  Store `records` as the zone with `apex` inside `view_name`.
  Replaces any prior copy of that apex within the same view;
  doesn't touch other views.

  ### Arguments

  * `view_name` — the view's name (binary).
  * `apex` — zone apex.
  * `records` — list of resource records.

  ### Returns

  * `:ok`.
  """
  @spec put_zone(binary(), binary(), [struct()]) :: :ok
  def put_zone(view_name, apex, records)
      when is_binary(view_name) and is_binary(apex) and is_list(records) do
    init()
    apex_norm = normalise(apex)
    key = {view_name, apex_norm}

    delete_zone(view_name, apex_norm)

    table =
      :ets.new(:view_zone_table, [
        :set,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])

    Enum.each(records, fn record -> insert_record(table, record) end)
    :ets.insert(@index_table, {key, table})
    :ok
  end

  @doc """
  Remove a zone from a view. Safe when the apex isn't in the
  view.
  """
  @spec delete_zone(binary(), binary()) :: :ok
  def delete_zone(view_name, apex) when is_binary(view_name) and is_binary(apex) do
    init()
    apex_norm = normalise(apex)
    key = {view_name, apex_norm}

    case :ets.lookup(@index_table, key) do
      [{^key, table}] ->
        try do
          :ets.delete(table)
        rescue
          ArgumentError -> :ok
        end

        :ets.delete(@index_table, key)
        :ok

      [] ->
        :ok
    end
  end

  @doc """
  Lookup an RRset in a view. Returns `:miss` when the view
  doesn't have the apex, OR has the apex but no matching
  RRset.

  ### Arguments

  * `view_name` — the view's name.
  * `qname` — the queried name.
  * `qtype` — the queried qtype atom.

  ### Returns

  * `{:ok, apex, [record, …]}` on hit.
  * `{:error, :nxdomain}` when the view owns a zone covering
    qname but has no record at that name+type.
  * `:miss` when no zone in this view covers qname.
  """
  @spec lookup(binary(), binary(), atom()) ::
          {:ok, binary(), [struct()]} | {:error, :nxdomain} | :miss
  def lookup(view_name, qname, qtype)
      when is_binary(view_name) and is_binary(qname) and is_atom(qtype) do
    init()

    case find_zone(view_name, qname) do
      nil ->
        :miss

      apex ->
        key = {view_name, apex}

        case :ets.lookup(@index_table, key) do
          [{^key, table}] ->
            qname_norm = normalise(qname)

            case :ets.lookup(table, {qname_norm, qtype}) do
              [{_, records}] -> {:ok, apex, records}
              [] -> {:error, :nxdomain}
            end

          [] ->
            :miss
        end
    end
  end

  @doc """
  Find the apex of the view-zone whose suffix most closely
  matches `qname`, or `nil` when this view doesn't host any
  ancestor of qname.
  """
  @spec find_zone(binary(), binary()) :: binary() | nil
  def find_zone(view_name, qname) when is_binary(view_name) and is_binary(qname) do
    init()
    qname_norm = normalise(qname)

    @index_table
    |> :ets.match_object({{view_name, :"$1"}, :"$2"})
    |> Enum.map(fn {{_view, apex}, _table} -> apex end)
    |> Enum.filter(fn apex -> name_under?(qname_norm, apex) end)
    |> Enum.max_by(&byte_size/1, fn -> nil end)
  end

  @doc """
  Return every apex registered in `view_name`.
  """
  @spec zones(binary()) :: [binary()]
  def zones(view_name) when is_binary(view_name) do
    init()

    @index_table
    |> :ets.match_object({{view_name, :"$1"}, :"$2"})
    |> Enum.map(fn {{_view, apex}, _table} -> apex end)
  end

  @doc "Drop every zone in every view. Test helper."
  @spec clear() :: :ok
  def clear do
    init()

    try do
      for {{_, _}, table} <- :ets.tab2list(@index_table) do
        try do
          :ets.delete(table)
        rescue
          ArgumentError -> :ok
        end
      end

      :ets.delete_all_objects(@index_table)
    rescue
      ArgumentError -> :ok
    end

    :ok
  end

  # ----- internals --------------------------------------------------

  defp insert_record(table, record) do
    name = normalise(record.name)
    type = type_of(record)

    case :ets.lookup(table, {name, type}) do
      [{key, existing}] -> :ets.insert(table, {key, [record | existing]})
      [] -> :ets.insert(table, {{name, type}, [record]})
    end
  end

  defp type_of(%module{}) do
    module
    |> Module.split()
    |> List.last()
    |> String.downcase()
    |> String.to_existing_atom()
  end

  defp normalise(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end

  defp name_under?(qname, apex), do: qname == apex or String.ends_with?(qname, "." <> apex)
end
