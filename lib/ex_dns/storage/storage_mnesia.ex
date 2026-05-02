defmodule ExDns.Storage.Mnesia do
  @behaviour ExDns.Storage

  @moduledoc """
  Mnesia-backed zone storage for clustered ExDns deployments.

  Implements the `ExDns.Storage` behaviour with the same semantics as
  `ExDns.Storage.ETS` but persists records in Mnesia tables that are
  replicated to every node in the cluster (`:ram_copies` everywhere).

  ## Tables

  * `ex_dns_records` (set) — `{{apex, name, type}, records}`
  * `ex_dns_zone_apexes` (set) — `{apex, true}` (index of loaded zones)
  * `ex_dns_zone_names` (set) — `{{apex, name}, true}` (name-existence
    index for NODATA detection)

  All three are `:ram_copies` on every node by default. Writes go
  through Mnesia transactions so they atomically replicate across
  the cluster.

  ## Lifecycle

  `init/0` ensures the local schema, the tables, and copies on this
  node. It is safe to call from `Application.start/2` on every node;
  the function uses `:mnesia.create_table` defensively.

  When new nodes join the cluster, the `ExDns.Cluster` supervisor adds
  them to the table copy lists.

  """

  @records_table :ex_dns_records
  @zones_table :ex_dns_zone_apexes
  @names_table :ex_dns_zone_names

  @impl ExDns.Storage
  def init do
    :ok = ensure_schema()
    :ok = :mnesia.start() |> normalize_start()
    :ok = ensure_table(@records_table, [type: :set, attributes: [:key, :records]])
    :ok = ensure_table(@zones_table, [type: :set, attributes: [:apex, :present]])
    :ok = ensure_table(@names_table, [type: :set, attributes: [:key, :present]])

    case :mnesia.wait_for_tables([@records_table, @zones_table, @names_table], 5_000) do
      :ok -> :ok
      {:timeout, _} = err -> {:error, err}
      other -> other
    end

    :ok
  end

  @doc """
  Adds the given node to the table copy list for every ExDns table on
  this node. Called by `ExDns.Cluster` when a new node joins.
  """
  @spec add_node(node()) :: :ok
  def add_node(node) when is_atom(node) do
    Enum.each([@records_table, @zones_table, @names_table], fn table ->
      :mnesia.add_table_copy(table, node, :ram_copies)
    end)

    :ok
  end

  @impl ExDns.Storage
  def put_zone(apex, records) when is_binary(apex) and is_list(records) do
    init()
    apex = normalize(apex)

    transaction(fn ->
      delete_zone_in_tx(apex)
      :mnesia.write({@zones_table, apex, true})

      Enum.each(records, fn record -> insert_record_in_tx(apex, record) end)
    end)
  end

  defp insert_record_in_tx(apex, record) do
    name = record |> Map.fetch!(:name) |> normalize()
    type = type_for_struct(record)
    key = {apex, name, type}

    existing =
      case :mnesia.read({@records_table, key}) do
        [{@records_table, ^key, records}] -> records
        [] -> []
      end

    :mnesia.write({@records_table, key, existing ++ [record]})
    :mnesia.write({@names_table, {apex, name}, true})
  end

  @impl ExDns.Storage
  def delete_zone(apex) when is_binary(apex) do
    init()
    apex = normalize(apex)
    transaction(fn -> delete_zone_in_tx(apex) end)
  end

  defp delete_zone_in_tx(apex) do
    record_keys =
      :mnesia.match_object({@records_table, {apex, :_, :_}, :_})
      |> Enum.map(fn {@records_table, key, _records} -> key end)

    name_keys =
      :mnesia.match_object({@names_table, {apex, :_}, :_})
      |> Enum.map(fn {@names_table, key, _} -> key end)

    Enum.each(record_keys, &:mnesia.delete({@records_table, &1}))
    Enum.each(name_keys, &:mnesia.delete({@names_table, &1}))
    :mnesia.delete({@zones_table, apex})
  end

  @impl ExDns.Storage
  def zones do
    init()

    case :mnesia.dirty_select(@zones_table, [{{@zones_table, :"$1", :_}, [], [:"$1"]}]) do
      apexes when is_list(apexes) -> apexes
      _ -> []
    end
  end

  @impl ExDns.Storage
  def find_zone(qname) when is_binary(qname) do
    init()
    qname = normalize(qname)

    zones()
    |> Enum.filter(fn apex -> apex == qname or String.ends_with?(qname, "." <> apex) end)
    |> Enum.max_by(&byte_size/1, fn -> nil end)
  end

  @impl ExDns.Storage
  def lookup(qname, qtype) when is_binary(qname) and is_atom(qtype) do
    case find_zone(qname) do
      nil -> {:error, :nxdomain}
      apex -> lookup(apex, qname, qtype)
    end
  end

  @impl ExDns.Storage
  def lookup(apex, qname, qtype)
      when is_binary(apex) and is_binary(qname) and is_atom(qtype) do
    init()
    apex = normalize(apex)
    qname = normalize(qname)

    case :mnesia.dirty_read({@records_table, {apex, qname, qtype}}) do
      [{@records_table, _, records}] ->
        {:ok, apex, records}

      [] ->
        if name_exists_in_zone?(apex, qname) do
          {:ok, apex, []}
        else
          {:error, :nxdomain}
        end
    end
  end

  defp name_exists_in_zone?(apex, qname) do
    case :mnesia.dirty_read({@names_table, {apex, qname}}) do
      [_] -> true
      [] -> false
    end
  end

  @impl ExDns.Storage
  def lookup_any(qname) when is_binary(qname) do
    case find_zone(qname) do
      nil -> {:error, :nxdomain}
      apex -> lookup_any(apex, qname)
    end
  end

  @impl ExDns.Storage
  def lookup_any(apex, qname) when is_binary(apex) and is_binary(qname) do
    init()
    apex = normalize(apex)
    qname = normalize(qname)

    pattern = {@records_table, {apex, qname, :_}, :"$1"}

    records =
      :mnesia.dirty_select(@records_table, [{pattern, [], [:"$1"]}])
      |> List.flatten()

    case records do
      [] -> {:error, :nxdomain}
      _ -> {:ok, apex, records}
    end
  end

  @impl ExDns.Storage
  def lookup_wildcard(qname, qtype) when is_binary(qname) and is_atom(qtype) do
    init()
    qname = normalize(qname)

    case find_zone(qname) do
      nil -> {:error, :nxdomain}
      apex -> walk_wildcards(apex, qname, qname, qtype)
    end
  end

  defp walk_wildcards(_apex, _qname, "", _qtype), do: {:error, :nxdomain}

  defp walk_wildcards(apex, qname, current, qtype) do
    case parent(current) do
      nil ->
        {:error, :nxdomain}

      parent ->
        below_or_at_apex? = parent == apex or String.ends_with?(parent, "." <> apex)

        cond do
          current != qname and name_exists_in_zone?(apex, current) ->
            {:error, :nxdomain}

          true ->
            wildcard_name = "*." <> parent

            case :mnesia.dirty_read({@records_table, {apex, wildcard_name, qtype}}) do
              [{@records_table, _, [_ | _] = records}] ->
                {:ok, apex, records}

              [] when below_or_at_apex? ->
                walk_wildcards(apex, qname, parent, qtype)

              _ ->
                {:error, :nxdomain}
            end
        end
    end
  end

  @impl ExDns.Storage
  def wildcard_name_exists?(qname) when is_binary(qname) do
    init()
    qname = normalize(qname)

    case find_zone(qname) do
      nil -> false
      apex -> walk_wildcard_existence(apex, qname, qname)
    end
  end

  defp walk_wildcard_existence(_apex, _qname, ""), do: false

  defp walk_wildcard_existence(apex, qname, current) do
    case parent(current) do
      nil ->
        false

      parent ->
        below_or_at_apex? = parent == apex or String.ends_with?(parent, "." <> apex)

        cond do
          current != qname and name_exists_in_zone?(apex, current) ->
            false

          true ->
            wildcard_name = "*." <> parent

            if name_exists_in_zone?(apex, wildcard_name) do
              {:ok, apex}
            else
              if below_or_at_apex?, do: walk_wildcard_existence(apex, qname, parent), else: false
            end
        end
    end
  end

  @impl ExDns.Storage
  def find_delegation(qname) when is_binary(qname) do
    init()
    qname = normalize(qname)

    case find_zone(qname) do
      nil ->
        :no_delegation

      apex ->
        qname
        |> ancestor_chain(apex)
        |> Enum.find_value(:no_delegation, fn name ->
          case :mnesia.dirty_read({@records_table, {apex, name, :ns}}) do
            [{@records_table, _, [_ | _] = records}] -> {:ok, apex, name, records}
            _ -> nil
          end
        end)
    end
  end

  @impl ExDns.Storage
  def dump_zone(apex) when is_binary(apex) do
    init()
    apex = normalize(apex)

    case :mnesia.dirty_read({@zones_table, apex}) do
      [] ->
        {:error, :not_loaded}

      _ ->
        pattern = {@records_table, {apex, :_, :_}, :"$1"}

        all_records =
          :mnesia.dirty_select(@records_table, [{pattern, [], [:"$1"]}])
          |> List.flatten()

        {soa, rest} = Enum.split_with(all_records, &match?(%ExDns.Resource.SOA{}, &1))
        {:ok, soa ++ rest}
    end
  end

  # ----- helpers -------------------------------------------------------

  @doc """
  Normalizes a domain name (lower-case ASCII, strip trailing dot).
  Public so that callers can pre-normalise.
  """
  def normalize(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end

  defp ancestor_chain(qname, apex), do: do_ancestor_chain(qname, apex, [])

  defp do_ancestor_chain(name, apex, acc) when name == apex, do: Enum.reverse(acc)

  defp do_ancestor_chain(name, apex, acc) do
    case parent(name) do
      nil -> Enum.reverse([name | acc])
      parent -> do_ancestor_chain(parent, apex, [name | acc])
    end
  end

  defp parent(name) do
    case String.split(name, ".", parts: 2) do
      [_only] -> nil
      [_first, rest] -> rest
    end
  end

  defp type_for_struct(%module{}) do
    module
    |> Module.split()
    |> List.last()
    |> String.downcase()
    |> String.to_existing_atom()
  end

  defp transaction(fun) do
    case :mnesia.transaction(fun) do
      {:atomic, _} -> :ok
      {:aborted, reason} -> {:error, reason}
    end
  end

  defp ensure_schema do
    case :mnesia.create_schema([node()]) do
      :ok -> :ok
      {:error, {_, {:already_exists, _}}} -> :ok
      _other -> :ok
    end
  end

  defp ensure_table(name, options) do
    options = Keyword.put_new(options, :ram_copies, [node()])

    case :mnesia.create_table(name, options) do
      {:atomic, :ok} -> :ok
      {:aborted, {:already_exists, ^name}} -> :ok
      other -> other
    end
  end

  defp normalize_start(:ok), do: :ok
  defp normalize_start({:error, {_, {:already_started, _}}}), do: :ok
  defp normalize_start(other), do: other
end
