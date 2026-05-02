defmodule ExDns.Recursor.Cache do
  @moduledoc """
  TTL-aware ETS-backed cache for the recursive resolver.

  Each entry is keyed by `{name, type}` (case-folded name) and holds
  a list of resource records plus an expiry timestamp in monotonic
  seconds. Reads transparently drop entries whose TTL has elapsed.

  The cache is intentionally simple — no LRU, no size cap beyond an
  optional global maximum, no negative caching record-by-record.
  Negative caching is handled by storing the apex SOA returned in the
  AUTHORITY section under the qname/qtype the client asked for, with
  the SOA's MINIMUM as the cap.

  """

  @table :ex_dns_recursor_cache

  @doc """
  Initialises the cache table. Idempotent. Called from
  `ExDns.Application.start/2`.
  """
  @spec init() :: :ok
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

        :ok

      _ ->
        :ok
    end
  end

  @doc """
  Inserts an RRset into the cache.

  ### Arguments

  * `name` is the (case-insensitive) owner name.
  * `type` is the type atom.
  * `records` is a list of resource record structs.
  * `ttl` is the effective TTL in seconds — the cache will drop the
    entry once `now + ttl` has elapsed. Pass `0` to bypass caching.

  ### Returns

  * `:ok`.
  """
  @spec put(binary(), atom(), [struct()], non_neg_integer()) :: :ok
  def put(_name, _type, _records, 0), do: :ok

  def put(name, type, records, ttl) when is_integer(ttl) and ttl > 0 do
    init()
    expires_at = now() + ttl
    :ets.insert(@table, {{normalize(name), type}, records, expires_at})
    :ok
  end

  @doc """
  Looks up an RRset.

  ### Returns

  * `{:hit, records}` when a non-expired entry exists.
  * `:miss` otherwise.
  """
  @spec lookup(binary(), atom()) :: {:hit, [struct()]} | :miss
  def lookup(name, type) do
    init()
    key = {normalize(name), type}

    case :ets.lookup(@table, key) do
      [{^key, records, expires_at}] ->
        if expires_at > now() do
          {:hit, records}
        else
          :ets.delete(@table, key)
          :miss
        end

      [] ->
        :miss
    end
  end

  @doc "Removes every entry from the cache. Used by tests."
  @spec clear() :: :ok
  def clear do
    init()
    :ets.delete_all_objects(@table)
    :ok
  end

  @doc "Returns the number of (possibly expired) entries currently held."
  @spec size() :: non_neg_integer()
  def size do
    init()
    :ets.info(@table, :size)
  end

  defp now, do: :erlang.monotonic_time(:second)

  defp normalize(name) when is_binary(name) do
    name
    |> String.trim_trailing(".")
    |> String.downcase(:ascii)
  end
end
