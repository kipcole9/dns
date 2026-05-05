defmodule ExDns.BlackHole.Storage.EKV do
  @moduledoc """
  EKV-backed `ExDns.BlackHole.Storage` adapter.

  Cluster-replicates blocklists, allow/deny lists, groups,
  generic KV, and query log entries when EKV is configured
  for multiple members. Single-node deployments get the same
  code path with no configuration change.

  ## Layout

  Each row is a separate EKV key:

      blackhole/blocklist/<id>          -> blocklist row map
      blackhole/allow/<domain>          -> allow row map
      blackhole/deny/<domain>           -> deny row map
      blackhole/group/<id>              -> group row map
      blackhole/kv/<key>                -> generic kv value
      blackhole/qlog/<ts_ns_padded>     -> query log entry map

  Query log keys use a 20-digit zero-padded `ts_ns` so
  lexicographic scan order matches numeric time order. Reads
  walk the prefix in reverse for newest-first pagination.

  ## When to prefer SQLite

  This adapter stores every query log entry as a separate
  EKV record. That's fine at small to moderate query rates
  but becomes wasteful at high QPS — operators with heavy
  query log requirements should run with the SQLite adapter:

      config :ex_dns, :black_hole,
        storage: {ExDns.BlackHole.Storage.SQLite, [path: "..."]}
  """

  @behaviour ExDns.BlackHole.Storage

  alias ExDns.EKV

  @blocklist_prefix "blackhole/blocklist/"
  @allow_prefix "blackhole/allow/"
  @deny_prefix "blackhole/deny/"
  @group_prefix "blackhole/group/"
  @kv_prefix "blackhole/kv/"
  @qlog_prefix "blackhole/qlog/"

  @impl true
  def init(_options) do
    {:ok, %{}}
  end

  # ----- blocklists -------------------------------------------------

  @impl true
  def list_blocklists(_state) do
    @blocklist_prefix
    |> scan_values()
    |> Enum.sort_by(&Map.get(&1, "id", ""))
  end

  @impl true
  def put_blocklist(_state, %{} = attrs) do
    id = Map.get_lazy(attrs, "id", &generate_id/0)
    row = Map.put(attrs, "id", id)
    :ok = EKV.put(@blocklist_prefix <> id, row)
    {:ok, row}
  end

  @impl true
  def delete_blocklist(_state, id) do
    EKV.delete(@blocklist_prefix <> id)
    :ok
  end

  # ----- allowlist / denylist (identical shape) ---------------------

  @impl true
  def list_allow(_state) do
    @allow_prefix
    |> scan_values()
    |> Enum.sort_by(&Map.fetch!(&1, "domain"))
  end

  @impl true
  def put_allow(_state, %{} = attrs) do
    put_domain_row(@allow_prefix, attrs)
  end

  @impl true
  def delete_allow(_state, domain) do
    EKV.delete(@allow_prefix <> domain)
    :ok
  end

  @impl true
  def list_deny(_state) do
    @deny_prefix
    |> scan_values()
    |> Enum.sort_by(&Map.fetch!(&1, "domain"))
  end

  @impl true
  def put_deny(_state, %{} = attrs) do
    put_domain_row(@deny_prefix, attrs)
  end

  @impl true
  def delete_deny(_state, domain) do
    EKV.delete(@deny_prefix <> domain)
    :ok
  end

  defp put_domain_row(prefix, attrs) do
    domain = Map.fetch!(attrs, "domain")
    row = Map.put_new_lazy(attrs, "added_at", fn -> System.os_time(:second) end)
    :ok = EKV.put(prefix <> domain, row)
    {:ok, row}
  end

  # ----- groups -----------------------------------------------------

  @impl true
  def list_groups(_state) do
    @group_prefix
    |> scan_values()
    |> Enum.sort_by(&Map.fetch!(&1, "name"))
  end

  @impl true
  def put_group(_state, %{} = attrs) do
    id = Map.get_lazy(attrs, "id", &generate_id/0)

    row =
      attrs
      |> Map.put("id", id)
      |> Map.put_new("enabled", true)
      |> Map.put_new("cidrs", [])
      |> Map.put_new("blocklist_ids", [])

    :ok = EKV.put(@group_prefix <> id, row)
    {:ok, row}
  end

  @impl true
  def delete_group(_state, id) do
    EKV.delete(@group_prefix <> id)
    :ok
  end

  # ----- query log --------------------------------------------------

  @impl true
  def append_query_log(_state, %{} = entry) do
    ts_ns = Map.get_lazy(entry, "ts_ns", fn -> System.os_time(:nanosecond) end)
    row = Map.put(entry, "ts_ns", ts_ns)
    :ok = EKV.put(qlog_key(ts_ns), row)
    :ok
  end

  @impl true
  def read_query_log(_state, query) do
    limit = Map.get(query, :limit, 100) |> max(1) |> min(1000)
    cursor = Map.get(query, :cursor)

    rows =
      @qlog_prefix
      |> scan_values()
      |> Enum.sort_by(& &1["ts_ns"], :desc)

    rows =
      case cursor do
        nil -> rows
        ts_ns when is_integer(ts_ns) -> Enum.filter(rows, &(&1["ts_ns"] < ts_ns))
      end

    page = Enum.take(rows, limit)

    next_cursor =
      cond do
        length(rows) > limit and page != [] ->
          page |> List.last() |> Map.fetch!("ts_ns")

        true ->
          nil
      end

    %{rows: page, next_cursor: next_cursor}
  end

  @impl true
  def truncate_query_log(_state) do
    delete_prefix(@qlog_prefix)
  end

  @impl true
  def delete_query_log_before(_state, ts_ns) when is_integer(ts_ns) do
    @qlog_prefix
    |> EKV.scan()
    |> Enum.each(fn entry ->
      {key, value, _meta} = unpack(entry)

      if value["ts_ns"] < ts_ns do
        EKV.delete(key)
      end
    end)

    :ok
  end

  # ----- generic kv -------------------------------------------------

  @impl true
  def put_kv(_state, key, value) when is_binary(key) do
    :ok = EKV.put(@kv_prefix <> key, value)
    :ok
  end

  @impl true
  def get_kv(_state, key) when is_binary(key) do
    case EKV.lookup(@kv_prefix <> key) do
      nil -> :error
      value -> {:ok, value}
    end
  end

  # ----- internal helpers -------------------------------------------

  defp scan_values(prefix) do
    prefix
    |> EKV.scan()
    |> Enum.map(fn entry ->
      {_key, value, _meta} = unpack(entry)
      value
    end)
  end

  defp delete_prefix(prefix) do
    prefix
    |> EKV.scan()
    |> Enum.each(fn entry ->
      {key, _value, _meta} = unpack(entry)
      EKV.delete(key)
    end)

    :ok
  end

  defp unpack({key, value, meta}), do: {key, value, meta}
  defp unpack({key, value}), do: {key, value, nil}

  defp qlog_key(ts_ns) when is_integer(ts_ns) do
    @qlog_prefix <> String.pad_leading(Integer.to_string(ts_ns), 20, "0")
  end

  defp generate_id do
    :crypto.strong_rand_bytes(6) |> Base.url_encode64(padding: false)
  end
end
