defmodule ExDns.Recursor.Prefetch do
  @moduledoc """
  Background re-resolution of popular records before their TTL
  expires.

  ## Why

  Without prefetch, every record in a recursive cache hits at
  least one client query whose response is *gated* on the upstream
  round-trip — the unlucky client whose query arrived first after
  expiry. For high-traffic resolvers this is a sustained tail
  latency problem.

  Prefetch eliminates that for *popular* records: once the cache
  entry is inside the trailing prefetch window (default: last 10%%
  of the original TTL), the next client query both serves the
  still-fresh cached answer *and* fires a background task that
  re-resolves and overwrites the entry. Subsequent clients then
  hit a cache populated by the prefetch, never blocked.

  ## Dedup

  An ETS set tracks which `{name, qtype}` pairs already have a
  prefetch in flight. `maybe_prefetch/3` is idempotent: many
  concurrent client queries in the same prefetch window cause at
  most one upstream re-resolution, not one per client.

  ## Telemetry

  * `[:ex_dns, :recursor, :prefetch, :start]` — fired on each
    spawned prefetch.
  * `[:ex_dns, :recursor, :prefetch, :stop]` — fired when the
    prefetch finishes (with `:result => :ok | :error`).
  * `[:ex_dns, :recursor, :prefetch, :skipped]` — fired when a
    prefetch is requested but already in flight or out of window.

  Metadata: `%{qname, qtype}`.
  """

  alias ExDns.Recursor.Cache

  @table :ex_dns_recursor_prefetch_inflight

  @doc """
  Initialise the in-flight tracking table. Idempotent. Safe to
  call from `Application.start/2` or lazily on first use.
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
  If `{qname, qtype}` is inside its prefetch window and no
  prefetch is already in flight, spawn `refresher_fn` as an
  unlinked task.

  `refresher_fn` is a zero-arity function that the prefetch task
  invokes. Typical implementation: ignore the cache and
  re-iterate the qname/qtype upstream, then `Cache.put/4` the
  result.

  ### Arguments

  * `qname` is the qname to refresh.
  * `qtype` is the qtype atom.
  * `refresher_fn` is a 0-arity function that performs the
    re-resolution.

  ### Options

  * `:prefetch_fraction` — see `ExDns.Recursor.Cache.in_prefetch_window?/3`.
    Default: the value of `:ex_dns, :recursor_prefetch_fraction`
    or `0.1`.

  ### Returns

  * `:scheduled` when a prefetch task was started.
  * `:already_in_flight` when another prefetch for the same
    `{qname, qtype}` is currently running.
  * `:not_in_window` when the entry is fresh, expired, or absent.

  ### Examples

      iex> ExDns.Recursor.Prefetch.init()
      iex> ExDns.Recursor.Prefetch.maybe_prefetch("nothing.test", :a,
      ...>   fn -> :ok end)
      :not_in_window

  """
  @spec maybe_prefetch(binary(), atom(), (-> any()), keyword()) ::
          :scheduled | :already_in_flight | :not_in_window
  def maybe_prefetch(qname, qtype, refresher_fn, options \\ [])
      when is_function(refresher_fn, 0) do
    init()

    cond do
      not enabled?() ->
        emit_skipped(qname, qtype, :disabled)
        :not_in_window

      not Cache.in_prefetch_window?(qname, qtype, options) ->
        emit_skipped(qname, qtype, :not_in_window)
        :not_in_window

      not claim_in_flight({qname, qtype}) ->
        emit_skipped(qname, qtype, :already_in_flight)
        :already_in_flight

      true ->
        spawn_prefetch(qname, qtype, refresher_fn)
        :scheduled
    end
  end

  defp claim_in_flight(key) do
    # `insert_new` succeeds only when the key is absent → exactly
    # one caller wins the race and gets to launch the task.
    :ets.insert_new(@table, {key, true})
  end

  defp release(key) do
    :ets.delete(@table, key)
    :ok
  end

  defp spawn_prefetch(qname, qtype, refresher_fn) do
    started_at = System.monotonic_time()

    :telemetry.execute(
      [:ex_dns, :recursor, :prefetch, :start],
      %{count: 1},
      %{qname: qname, qtype: qtype}
    )

    Task.start(fn ->
      result =
        try do
          refresher_fn.()
          :ok
        rescue
          _ -> :error
        catch
          _, _ -> :error
        end

      release({qname, qtype})

      :telemetry.execute(
        [:ex_dns, :recursor, :prefetch, :stop],
        %{duration: System.monotonic_time() - started_at},
        %{qname: qname, qtype: qtype, result: result}
      )
    end)
  end

  defp emit_skipped(qname, qtype, reason) do
    :telemetry.execute(
      [:ex_dns, :recursor, :prefetch, :skipped],
      %{count: 1},
      %{qname: qname, qtype: qtype, reason: reason}
    )
  end

  defp enabled? do
    Application.get_env(:ex_dns, :recursor_prefetch_enabled, true)
  end

  @doc "Clear the in-flight tracking table. Test helper."
  @spec clear() :: :ok
  def clear do
    init()

    try do
      :ets.delete_all_objects(@table)
    rescue
      ArgumentError -> :ok
    end

    :ok
  end

  @doc "Returns the number of prefetches currently in flight."
  @spec in_flight_count() :: non_neg_integer()
  def in_flight_count do
    init()

    try do
      :ets.info(@table, :size)
    rescue
      ArgumentError -> 0
    end
  end
end
