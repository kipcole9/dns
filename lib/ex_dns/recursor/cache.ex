defmodule ExDns.Recursor.Cache do
  @moduledoc """
  TTL-aware ETS-backed cache for the recursive resolver, with
  proper RFC 2308 negative caching.

  ## Entry shapes

  Three logical entry kinds, all stored in the same ETS table:

  * `{:positive, records}` — keyed by `{name, qtype}`. Standard
    RRset cache.

  * `{:nodata, soa}` — keyed by `{name, qtype}`. The name exists
    but has no records of this type. RFC 2308 §3 / §5.

  * `{:nxdomain, soa}` — keyed by `{name, :nxdomain}`. The name
    does not exist at all. Single negative entry suffices for
    every qtype the client may ask about.

  Negative entries' TTL is capped at `min(SOA.minimum, SOA.ttl)`
  per RFC 2308 §5.

  ## Lookup precedence

  `lookup/2` returns the first matching entry in this order:

  1. Positive RRset for `{name, qtype}`.
  2. NODATA cache for `{name, qtype}`.
  3. NXDOMAIN cache for `{name, :nxdomain}` (the qtype is
     irrelevant for NXDOMAIN — the name itself is gone).

  This means a cached NXDOMAIN suppresses *every* subsequent query
  for that name without any upstream traffic.
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
  Inserts a positive RRset.

  ### Arguments

  * `name` is the (case-insensitive) owner name.
  * `type` is the qtype atom.
  * `records` is the RRset to cache.
  * `ttl` is the effective TTL in seconds; `0` bypasses caching.

  ### Returns

  * `:ok`.
  """
  @spec put(binary(), atom(), [struct()], non_neg_integer()) :: :ok
  def put(_name, _type, _records, 0), do: :ok

  def put(name, type, records, ttl) when is_integer(ttl) and ttl > 0 do
    init()
    expires_at = now() + ttl
    :ets.insert(@table, {{normalize(name), type}, :positive, records, expires_at})
    :ok
  end

  @doc """
  Cache a negative answer per RFC 2308.

  ### Arguments

  * `name` is the (case-insensitive) owner name.
  * `qtype` is the qtype the client asked about. Ignored for
    `:nxdomain`.
  * `kind` is `:nxdomain` or `:nodata`.
  * `soa` is the apex SOA returned in the AUTHORITY section. Its
    `:minimum` and `:ttl` together cap how long we cache.

  ### Returns

  * `:ok`.

  ### Examples

      iex> alias ExDns.Resource.SOA
      iex> ExDns.Recursor.Cache.clear()
      iex> ExDns.Recursor.Cache.put_negative("missing.test", :a, :nxdomain,
      ...>   %SOA{name: "test", ttl: 3600, class: :in, mname: "ns",
      ...>        email: "h", serial: 1, refresh: 1, retry: 1, expire: 1, minimum: 60})
      :ok

  """
  @spec put_negative(binary(), atom(), :nxdomain | :nodata, struct()) :: :ok
  def put_negative(name, qtype, kind, soa)

  def put_negative(name, _qtype, :nxdomain, %{} = soa) do
    init()
    ttl = negative_ttl(soa)
    expires_at = now() + ttl
    :ets.insert(@table, {{normalize(name), :nxdomain}, :nxdomain, soa, expires_at})
    :ok
  end

  def put_negative(name, qtype, :nodata, %{} = soa) do
    init()
    ttl = negative_ttl(soa)
    expires_at = now() + ttl
    :ets.insert(@table, {{normalize(name), qtype}, :nodata, soa, expires_at})
    :ok
  end

  @doc """
  Look up a name + qtype.

  ### Returns

  * `{:hit, records}` — positive answer.
  * `{:nodata, soa}` — cached NODATA (RFC 2308).
  * `{:nxdomain, soa}` — cached NXDOMAIN (RFC 2308).
  * `:miss` — nothing cached, or every match expired.

  ### Examples

      iex> ExDns.Recursor.Cache.clear()
      iex> ExDns.Recursor.Cache.lookup("nothing.test", :a)
      :miss

  """
  @spec lookup(binary(), atom()) ::
          {:hit, [struct()]}
          | {:nodata, struct()}
          | {:nxdomain, struct()}
          | :miss
  def lookup(name, type) do
    init()
    norm = normalize(name)

    result =
      lookup_entry({norm, type}) ||
        lookup_entry({norm, :nxdomain}) ||
        :miss

    emit_lookup_telemetry(result, name, type)
    result
  end

  defp lookup_entry(key) do
    case :ets.lookup(@table, key) do
      [{^key, kind, payload, expires_at}] ->
        if expires_at > now() do
          format_entry(kind, payload)
        else
          :ets.delete(@table, key)
          nil
        end

      _ ->
        nil
    end
  end

  defp format_entry(:positive, records), do: {:hit, records}
  defp format_entry(:nodata, soa), do: {:nodata, soa}
  defp format_entry(:nxdomain, soa), do: {:nxdomain, soa}

  defp emit_lookup_telemetry(:miss, name, type) do
    :telemetry.execute(
      [:ex_dns, :cache, :miss],
      %{count: 1},
      %{layer: :recursor, qname: name, qtype: type}
    )
  end

  defp emit_lookup_telemetry({kind, _}, name, type) do
    :telemetry.execute(
      [:ex_dns, :cache, :hit],
      %{count: 1},
      %{layer: :recursor, qname: name, qtype: type, kind: kind}
    )
  end

  @doc """
  Return every cached NSEC record whose owner is at or below
  `zone`, with non-expired TTLs.

  Used by `ExDns.DNSSEC.AggressiveNSEC` to short-circuit NXDOMAIN
  / NODATA on subsequent queries inside the same zone (RFC 8198).

  ### Arguments

  * `zone` is the apex of the zone whose NSEC chain is of
    interest, lower-cased and trimmed of any trailing dot.

  ### Returns

  * A list of `%NSEC{}` records currently in the cache.

  ### Examples

      iex> ExDns.Recursor.Cache.clear()
      iex> ExDns.Recursor.Cache.nsec_records_under("example.test")
      []

  """
  @spec nsec_records_under(binary()) :: [struct()]
  def nsec_records_under(zone) when is_binary(zone) do
    init()
    suffix = normalize(zone)
    now_secs = now()

    try do
      :ets.foldl(
        fn
          {{name, :nsec}, :positive, records, expires_at}, acc
          when is_binary(name) ->
            cond do
              expires_at <= now_secs -> acc
              not name_under?(name, suffix) -> acc
              true -> records ++ acc
            end

          _, acc ->
            acc
        end,
        [],
        @table
      )
    rescue
      ArgumentError -> []
    end
  end

  defp name_under?(name, ""), do: is_binary(name)

  defp name_under?(name, suffix) when is_binary(name) and is_binary(suffix) do
    name == suffix or String.ends_with?(name, "." <> suffix)
  end

  @doc "Removes every entry from the cache. Used by tests."
  @spec clear() :: :ok
  def clear do
    init()
    # The cache table is owned by whichever process happened to call
    # `init/0` first, and dies with that process. In tests, an
    # application restart between `init/0` and `delete_all_objects/1`
    # can leave a stale `@table` reference here, so swallow
    # ArgumentError defensively — `clear/0` is best-effort.
    try do
      :ets.delete_all_objects(@table)
    rescue
      ArgumentError -> :ok
    end

    :ok
  end

  @doc "Returns the number of (possibly expired) entries currently held."
  @spec size() :: non_neg_integer()
  def size do
    init()

    try do
      :ets.info(@table, :size)
    rescue
      ArgumentError -> 0
    end
  end

  # RFC 2308 §5: the negative-cache TTL is bounded by the smaller
  # of SOA.minimum and SOA.ttl.
  defp negative_ttl(%{minimum: minimum, ttl: ttl})
       when is_integer(minimum) and is_integer(ttl) do
    min(minimum, ttl)
  end

  defp negative_ttl(_), do: 0

  defp now, do: :erlang.monotonic_time(:second)

  defp normalize(name) when is_binary(name) do
    name
    |> String.trim_trailing(".")
    |> String.downcase(:ascii)
  end
end
