defmodule ExDns.Storage.ETS do
  @behaviour ExDns.Storage

  @moduledoc """
  ETS-backed in-memory zone storage for ExDns.

  ## Layout

  Two kinds of ETS tables are used:

  * **Index table** (`@index_table`) — a single named table mapping each
    zone's apex (a normalized lower-case domain name binary) to the
    `:ets` table identifier of the per-zone table that holds the zone's
    records.

  * **Per-zone tables** — one anonymous `:set` table per zone, with key
    `{normalized_name, type}` and value `[record, …]` (an RRset). Names
    are normalized to lower-case before storage and lookup, so DNS's
    case-insensitive comparison rule is honoured.

  ## Public API

  * `init/0` creates the index table. Idempotent.

  * `put_zone/2` registers a zone (name → list of records) and replaces
    any existing zone with the same apex.

  * `delete_zone/1` removes a zone.

  * `zones/0` returns the apexes currently loaded.

  * `find_zone/1` returns the apex of the zone with the longest suffix
    match against a given query name.

  * `lookup/2` and `lookup/3` find the RRset for `{name, type}` in the
    appropriate zone.

  """

  @index_table :ex_dns_zones

  @typedoc "A normalized (lower-case) domain name held as a binary."
  @type name :: binary()

  @typedoc "A DNS record type atom (e.g. `:a`, `:ns`)."
  @type type :: atom()

  @doc """
  Creates the index table if it does not already exist. Safe to call
  multiple times.

  ### Returns

  * `:ok`.

  """
  @spec init() :: :ok
  def init do
    case :ets.whereis(@index_table) do
      :undefined ->
        :ets.new(@index_table, [
          :set,
          :public,
          :named_table,
          read_concurrency: true,
          write_concurrency: true
        ])

        :ok

      _ref ->
        :ok
    end
  end

  @doc """
  Loads a zone into storage, replacing any zone already loaded under the
  same apex.

  ### Arguments

  * `apex` is the zone's origin (e.g. `"example.com"`). Case is folded
    for storage and lookup; trailing dots are stripped.

  * `records` is a list of resource record structs (per-type structs
    such as `%ExDns.Resource.A{}`). Each struct's `:name` field should
    be the fully qualified owner of that record.

  ### Returns

  * `:ok`.

  """
  @spec put_zone(binary(), [struct()]) :: :ok
  def put_zone(apex, records) when is_binary(apex) and is_list(records) do
    init()
    apex = normalize(apex)

    # Snapshot the previous zone (if any) so we can compute an IXFR
    # journal entry for the change. We do this *before* the in-place
    # delete so the diff is meaningful.
    previous_records =
      case dump_zone(apex) do
        {:ok, records} -> records
        {:error, :not_loaded} -> []
      end

    delete_zone(apex)

    table =
      :ets.new(:zone_table, [
        :set,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])

    Enum.each(records, fn record -> insert_record(table, record) end)
    :ets.insert(@index_table, {apex, table})

    # Record a journal entry. Failures (no SOA, no advance, no
    # previous zone) are silently ignored — they're normal during
    # initial load and shouldn't block the put.
    if previous_records != [] do
      _ = ExDns.Zone.Journal.record(apex, previous_records, records)
    end

    :ok
  end

  @doc """
  Removes a zone from storage. Safe to call when no such zone exists.
  """
  @spec delete_zone(binary()) :: :ok
  def delete_zone(apex) when is_binary(apex) do
    init()
    apex = normalize(apex)

    case :ets.lookup(@index_table, apex) do
      [{^apex, table}] ->
        try do
          :ets.delete(table)
        rescue
          ArgumentError -> :ok
        end

        :ets.delete(@index_table, apex)
        :ok

      [] ->
        :ok
    end
  end

  @doc """
  Returns the list of zone apexes currently loaded.
  """
  @spec zones() :: [binary()]
  def zones do
    init()
    @index_table |> :ets.tab2list() |> Enum.map(fn {apex, _table} -> apex end)
  end

  @doc """
  Returns the apex of the loaded zone whose suffix most closely matches
  `qname`, or `nil` if no loaded zone is responsible for `qname`.

  Longest-suffix match: querying `mail.host.example.com` against zones
  `example.com` and `host.example.com` returns `host.example.com`.

  """
  @spec find_zone(binary()) :: binary() | nil
  def find_zone(qname) when is_binary(qname) do
    init()
    qname = normalize(qname)
    apexes = @index_table |> :ets.tab2list() |> Enum.map(fn {apex, _} -> apex end)

    apexes
    |> Enum.filter(fn apex -> apex == qname or String.ends_with?(qname, "." <> apex) end)
    |> Enum.max_by(&byte_size/1, fn -> nil end)
  end

  @doc """
  Looks up the RRset for `{qname, qtype}` across all loaded zones.

  ### Arguments

  * `qname` is the query name.

  * `qtype` is the DNS type atom (e.g. `:a`).

  ### Returns

  * `{:ok, apex, [record, …]}` — `apex` is the zone the records came
    from; the record list is empty when the name exists in the zone but
    has no records of the requested type (NODATA).

  * `{:error, :nxdomain}` — `qname` does not fall under any loaded zone,
    or it does but has no records of any type.

  """
  @spec lookup(binary(), type()) ::
          {:ok, binary(), [struct()]} | {:error, :nxdomain}
  def lookup(qname, qtype) when is_binary(qname) and is_atom(qtype) do
    case find_zone(qname) do
      nil -> {:error, :nxdomain}
      apex -> lookup(apex, qname, qtype)
    end
  end

  @doc """
  Like `lookup/2`, but skips the zone-search step by accepting the apex
  directly.
  """
  @spec lookup(binary(), binary(), type()) ::
          {:ok, binary(), [struct()]} | {:error, :nxdomain}
  def lookup(apex, qname, qtype)
      when is_binary(apex) and is_binary(qname) and is_atom(qtype) do
    init()
    apex = normalize(apex)
    qname = normalize(qname)

    case :ets.lookup(@index_table, apex) do
      [{^apex, table}] ->
        case :ets.lookup(table, {qname, qtype}) do
          [{_key, records}] ->
            {:ok, apex, records}

          [] ->
            if name_exists?(table, qname) do
              {:ok, apex, []}
            else
              {:error, :nxdomain}
            end
        end

      [] ->
        {:error, :nxdomain}
    end
  end

  @doc """
  Returns every RRset stored at `qname`, regardless of type.

  Used to answer ANY (qtype = 255) queries.

  ### Returns

  * `{:ok, apex, [record, …]}` — `apex` is the zone the records came
    from. The record list is empty when the name is present in the zone
    but has no records (rare; e.g. a parent name created only by glue).

  * `{:error, :nxdomain}` — `qname` is not present under any loaded
    zone, or it is but the zone has no records at it.

  """
  @spec lookup_any(binary()) :: {:ok, binary(), [struct()]} | {:error, :nxdomain}
  def lookup_any(qname) when is_binary(qname) do
    case find_zone(qname) do
      nil -> {:error, :nxdomain}
      apex -> lookup_any(apex, qname)
    end
  end

  @doc """
  Like `lookup_any/1`, but skips zone search by accepting the apex
  directly.
  """
  @spec lookup_any(binary(), binary()) :: {:ok, binary(), [struct()]} | {:error, :nxdomain}
  def lookup_any(apex, qname) when is_binary(apex) and is_binary(qname) do
    init()
    apex = normalize(apex)
    qname = normalize(qname)

    case :ets.lookup(@index_table, apex) do
      [{^apex, table}] ->
        records =
          :ets.foldl(
            fn
              {{^qname, _type}, rrs}, acc -> rrs ++ acc
              _entry, acc -> acc
            end,
            [],
            table
          )

        case records do
          [] -> {:error, :nxdomain}
          _ -> {:ok, apex, records}
        end

      [] ->
        {:error, :nxdomain}
    end
  end

  @doc """
  Looks up a wildcard match for `{qname, qtype}` per RFC 4592.

  Walks the labels of `qname` from the closest ancestor up towards the
  apex. At each ancestor `<anc>`, looks for `*.<anc>`. The closest
  matching wildcard wins, but only if no explicit name sits between the
  wildcard and `qname` (RFC 4592 §2.2 "closer encloser" rule).

  ### Returns

  * `{:ok, apex, [record, …]}` — wildcard match found; the records'
    owner names are NOT rewritten to `qname` here, that is the
    resolver's responsibility.

  * `{:error, :nxdomain}` — no wildcard applies.

  """
  @spec lookup_wildcard(binary(), type()) ::
          {:ok, binary(), [struct()]} | {:error, :nxdomain}
  def lookup_wildcard(qname, qtype) when is_binary(qname) and is_atom(qtype) do
    init()
    qname = normalize(qname)

    case find_zone(qname) do
      nil -> {:error, :nxdomain}
      apex -> walk_wildcards(apex, qname, qtype)
    end
  end

  defp walk_wildcards(apex, qname, qtype) do
    case :ets.lookup(@index_table, apex) do
      [] -> {:error, :nxdomain}
      [{^apex, table}] -> walk_wildcards(table, apex, qname, qname, qtype)
    end
  end

  defp walk_wildcards(_table, _apex, _qname, "", _qtype), do: {:error, :nxdomain}

  defp walk_wildcards(table, apex, qname, current, qtype) do
    case parent(current) do
      nil ->
        {:error, :nxdomain}

      parent ->
        # Stop walking once we've climbed above the apex.
        below_or_at_apex? = parent == apex or String.ends_with?(parent, "." <> apex)

        cond do
          # The "closer encloser" check: if any name strictly between
          # the wildcard candidate and qname exists in the zone, the
          # wildcard does NOT apply.
          current != qname and explicit_name_exists?(table, current) ->
            {:error, :nxdomain}

          true ->
            wildcard_name = "*." <> parent

            case :ets.lookup(table, {wildcard_name, qtype}) do
              [{_key, records}] when records != [] ->
                {:ok, apex, records}

              [] when below_or_at_apex? ->
                walk_wildcards(table, apex, qname, parent, qtype)

              _ ->
                {:error, :nxdomain}
            end
        end
    end
  end

  defp parent(name) do
    case String.split(name, ".", parts: 2) do
      [_only] -> nil
      [_first, rest] -> rest
    end
  end

  defp explicit_name_exists?(table, name) do
    name_exists?(table, name)
  end

  @doc """
  Returns every resource record stored in the zone with the given apex,
  ordered with the SOA first.

  Used by AXFR to stream the zone over TCP.

  ### Returns

  * `{:ok, [record, …]}` when the zone is loaded.
  * `{:error, :not_loaded}` when no zone is loaded for `apex`.
  """
  @spec dump_zone(binary()) :: {:ok, [struct()]} | {:error, :not_loaded}
  def dump_zone(apex) when is_binary(apex) do
    init()
    apex = normalize(apex)

    case :ets.lookup(@index_table, apex) do
      [{^apex, table}] ->
        all_records = :ets.foldl(fn {{_name, _type}, rrs}, acc -> rrs ++ acc end, [], table)
        {soa, rest} = Enum.split_with(all_records, &match?(%ExDns.Resource.SOA{}, &1))
        {:ok, soa ++ rest}

      [] ->
        {:error, :not_loaded}
    end
  end

  @doc """
  Returns the closest delegation point at-or-above `qname` within the
  zone responsible for `qname`.

  A delegation point is any name that has NS records and is not the zone
  apex. When the resolver finds one, it should respond with those NS
  records in the AUTHORITY section (and any glue A/AAAA in ADDITIONAL)
  rather than answering the query itself.

  ### Returns

  * `{:ok, apex, delegation_name, [%NS{}, …]}` when a delegation applies.

  * `:no_delegation` when no NS cut exists at-or-above `qname` within the
    zone (or when `qname` is not under any loaded zone).

  """
  @spec find_delegation(binary()) ::
          {:ok, binary(), binary(), [struct()]} | :no_delegation
  def find_delegation(qname) when is_binary(qname) do
    init()
    qname = normalize(qname)

    case find_zone(qname) do
      nil ->
        :no_delegation

      apex ->
        case :ets.lookup(@index_table, apex) do
          [] -> :no_delegation
          [{^apex, table}] -> find_delegation(table, apex, qname)
        end
    end
  end

  defp find_delegation(table, apex, qname) do
    # Walk from qname up to (but not including) apex, looking for the
    # closest name that has NS records.
    qname
    |> ancestor_chain(apex)
    |> Enum.find_value(:no_delegation, fn name ->
      case :ets.lookup(table, {name, :ns}) do
        [{_key, [_ | _] = records}] ->
          {:ok, apex, name, records}

        _ ->
          nil
      end
    end)
  end

  # Returns the list of names from qname (inclusive) up to but NOT
  # including apex. If qname == apex returns [].
  defp ancestor_chain(qname, apex) do
    do_ancestor_chain(qname, apex, [])
  end

  defp do_ancestor_chain(name, apex, acc) when name == apex, do: Enum.reverse(acc)

  defp do_ancestor_chain(name, apex, acc) do
    case parent(name) do
      nil -> Enum.reverse([name | acc])
      parent -> do_ancestor_chain(parent, apex, [name | acc])
    end
  end

  @doc """
  Returns `{:ok, apex}` if some wildcard `*.<ancestor>` exists for any
  type that would synthesise an answer for `qname`. Used by the resolver
  to distinguish NODATA from NXDOMAIN when the wildcard exists but does
  not have records of the requested type.
  """
  @spec wildcard_name_exists?(binary()) :: {:ok, binary()} | false
  def wildcard_name_exists?(qname) when is_binary(qname) do
    init()
    qname = normalize(qname)

    case find_zone(qname) do
      nil -> false
      apex -> wildcard_name_exists?(apex, qname)
    end
  end

  defp wildcard_name_exists?(apex, qname) do
    case :ets.lookup(@index_table, apex) do
      [] ->
        false

      [{^apex, table}] ->
        if walk_wildcard_existence(table, apex, qname, qname) do
          {:ok, apex}
        else
          false
        end
    end
  end

  defp walk_wildcard_existence(_table, _apex, _qname, ""), do: false

  defp walk_wildcard_existence(table, apex, qname, current) do
    case parent(current) do
      nil ->
        false

      parent ->
        below_or_at_apex? = parent == apex or String.ends_with?(parent, "." <> apex)

        cond do
          current != qname and explicit_name_exists?(table, current) ->
            false

          true ->
            wildcard_name = "*." <> parent

            if name_exists?(table, wildcard_name) do
              true
            else
              below_or_at_apex? and walk_wildcard_existence(table, apex, qname, parent)
            end
        end
    end
  end

  defp name_exists?(table, qname) do
    :ets.foldl(
      fn
        {{^qname, _type}, _records}, _acc -> true
        _entry, acc -> acc
      end,
      false,
      table
    )
  end

  defp insert_record(table, record) do
    name = record |> Map.fetch!(:name) |> normalize()
    type = type_for_struct(record)
    key = {name, type}

    existing =
      case :ets.lookup(table, key) do
        [{^key, records}] -> records
        [] -> []
      end

    :ets.insert(table, {key, existing ++ [record]})
  end

  defp type_for_struct(%module{}) do
    module
    |> Module.split()
    |> List.last()
    |> String.downcase()
    |> String.to_existing_atom()
  end

  @doc """
  Normalizes a domain name for case-insensitive comparison and storage:
  lower-cases ASCII and strips a single trailing dot.
  """
  @spec normalize(binary()) :: binary()
  def normalize(name) when is_binary(name) do
    name
    |> String.trim_trailing(".")
    |> String.downcase(:ascii)
  end
end
