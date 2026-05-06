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

  # Hard upper bound on cache size. A random-subdomain attack
  # against the recursor (water torture: query
  # <random>.<target> for many randoms) would otherwise grow
  # the table without bound and OOM the BEAM. The default
  # carries every realistic working set; operators with very
  # large recursor footprints can raise it via
  # `:ex_dns, :recursor_cache, [max_entries: 500_000]`.
  @default_max_entries 100_000

  # When the cap is hit and no expired entries can be reaped,
  # drop this fraction of the table (closest-to-expiry first).
  # Bigger fraction → fewer expensive evictions but lumpier
  # latency; 10% is a sane middle ground.
  @evict_fraction 0.10

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
    maybe_evict()
    expires_at = now() + ttl
    :ets.insert(@table, {{normalize(name), type}, :positive, records, expires_at, ttl})
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
    maybe_evict()
    ttl = negative_ttl(soa)
    expires_at = now() + ttl
    :ets.insert(@table, {{normalize(name), :nxdomain}, :nxdomain, soa, expires_at, ttl})
    :ok
  end

  def put_negative(name, qtype, :nodata, %{} = soa) do
    init()
    maybe_evict()
    ttl = negative_ttl(soa)
    expires_at = now() + ttl
    :ets.insert(@table, {{normalize(name), qtype}, :nodata, soa, expires_at, ttl})
    :ok
  end

  # Cap-the-cache hook called from every `put*`. Cheap when
  # we are under the cap (single ets:info call); only does
  # real work when the table is at its limit. The first line
  # of defence is sweeping expired entries (free wins); only
  # if the live set is itself over budget do we drop fresh
  # entries by closest-to-expiry.
  defp maybe_evict do
    cap = max_entries()

    if :ets.info(@table, :size) >= cap do
      reap_expired()

      if :ets.info(@table, :size) >= cap do
        evict_closest_to_expiry(round(cap * @evict_fraction))
      end
    end

    :ok
  end

  defp reap_expired do
    cutoff = now()

    :ets.select_delete(@table, [
      {{:_, :_, :_, :"$1", :_}, [{:"=<", :"$1", cutoff}], [true]}
    ])
  end

  # Best-effort eviction: pull every entry out, sort by
  # `expires_at`, drop the `count` most-soon-to-expire. This
  # is O(n log n) and only runs on the (rare) `put` that
  # tips the table over the cap with no expired entries to
  # reap. For the default 100k-entry cap this is a few tens
  # of milliseconds; rare enough not to matter.
  defp evict_closest_to_expiry(count) when count > 0 do
    @table
    |> :ets.tab2list()
    |> Enum.sort_by(fn entry -> elem(entry, 3) end)
    |> Enum.take(count)
    |> Enum.each(fn entry -> :ets.delete(@table, elem(entry, 0)) end)
  end

  defp evict_closest_to_expiry(_), do: :ok

  defp max_entries do
    Application.get_env(:ex_dns, :recursor_cache, [])
    |> Keyword.get(:max_entries, @default_max_entries)
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
      [{^key, kind, payload, expires_at, _orig_ttl}] ->
        cond do
          expires_at > now() ->
            format_entry(kind, payload)

          past_stale_window?(expires_at) ->
            :ets.delete(@table, key)
            nil

          true ->
            # Past hard TTL but still inside the serve-stale window:
            # don't delete, but `lookup/2` still treats it as a miss.
            # `lookup_stale/2` will pick it up.
            nil
        end

      _ ->
        nil
    end
  end

  defp past_stale_window?(expires_at) do
    expires_at + serve_stale_max() <= now()
  end

  defp serve_stale_max do
    Application.get_env(:ex_dns, :recursor_serve_stale_ttl, 0)
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
  Look up a name + qtype, including expired entries within the
  serve-stale window (RFC 8767).

  Distinct from `lookup/2`: this returns `{:stale, records, age_secs}`
  for entries past their TTL but still inside the configured
  `:recursor_serve_stale_ttl` window. Callers (the iterator)
  invoke this only after upstream resolution fails.

  ### Returns

  * `{:hit, records}` — fresh positive answer.
  * `{:nodata, soa}` — fresh cached NODATA.
  * `{:nxdomain, soa}` — fresh cached NXDOMAIN.
  * `{:stale, records, age_secs}` — expired positive answer still
    within the serve-stale window. `age_secs` is how many seconds
    ago the entry expired.
  * `:miss` — nothing cached, or every match past the stale window.

  ### Examples

      iex> ExDns.Recursor.Cache.clear()
      iex> ExDns.Recursor.Cache.lookup_stale("nothing.test", :a)
      :miss

  """
  @spec lookup_stale(binary(), atom()) ::
          {:hit, [struct()]}
          | {:nodata, struct()}
          | {:nxdomain, struct()}
          | {:stale, [struct()], non_neg_integer()}
          | :miss
  def lookup_stale(name, type) do
    init()
    norm = normalize(name)

    case lookup_entry_with_stale({norm, type}) do
      nil -> lookup_entry_with_stale({norm, :nxdomain}) || :miss
      result -> result
    end
  end

  defp lookup_entry_with_stale(key) do
    case :ets.lookup(@table, key) do
      [{^key, kind, payload, expires_at, _orig_ttl}] ->
        now_s = now()

        cond do
          expires_at > now_s ->
            format_entry(kind, payload)

          past_stale_window?(expires_at) ->
            :ets.delete(@table, key)
            nil

          kind == :positive ->
            {:stale, payload, now_s - expires_at}

          true ->
            # Negative entries are not served stale.
            nil
        end

      _ ->
        nil
    end
  end

  @doc """
  Returns `true` when the cached `{name, type}` entry is inside
  its prefetch window — the trailing `prefetch_fraction` of its
  original TTL.

  Used by `ExDns.Recursor.Prefetch` so the iterator can fire an
  asynchronous re-resolution before a popular record actually
  expires.

  ### Arguments

  * `name` is the (case-insensitive) owner name.
  * `type` is the qtype atom.

  ### Options

  * `:prefetch_fraction` — fraction (0.0–1.0) of the original TTL
    that defines the trailing prefetch window. Default `0.1` (the
    last 10%% of the TTL).

  ### Returns

  * `true` when a non-expired positive entry is inside the
    trailing window.
  * `false` otherwise (no entry, expired entry, or fresh entry
    still outside the window).

  ### Examples

      iex> ExDns.Recursor.Cache.clear()
      iex> ExDns.Recursor.Cache.in_prefetch_window?("nothing.test", :a)
      false

  """
  @spec in_prefetch_window?(binary(), atom(), keyword()) :: boolean()
  def in_prefetch_window?(name, type, options \\ []) do
    init()
    fraction = Keyword.get(options, :prefetch_fraction, prefetch_fraction_default())

    case :ets.lookup(@table, {normalize(name), type}) do
      [{_, :positive, _payload, expires_at, original_ttl}]
      when is_integer(original_ttl) and original_ttl > 0 ->
        now_s = now()
        threshold = expires_at - trunc(original_ttl * fraction)
        expires_at > now_s and now_s >= threshold

      _ ->
        false
    end
  end

  defp prefetch_fraction_default do
    Application.get_env(:ex_dns, :recursor_prefetch_fraction, 0.1)
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
          {{name, :nsec}, :positive, records, expires_at, _orig_ttl}, acc
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
