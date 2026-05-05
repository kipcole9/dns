defmodule ExDns.API.MetricsCounters do
  @moduledoc """
  Lightweight in-process counter aggregator for the
  `/api/v1/metrics/summary` endpoint.

  ## What we count

  * **Queries** — `[:ex_dns, :query, :start]`, bucketed by
    qtype.
  * **RRL drops** — `[:ex_dns, :rrl, :drop]`, single counter.
  * **Cache hits / misses** — `[:ex_dns, :cache, :hit]` /
    `[:ex_dns, :cache, :miss]`.
  * **DNSSEC validation outcomes** —
    `[:ex_dns, :dnssec, :validate, :stop]`, bucketed by
    `:status` (`:secure | :insecure | :bogus | :indeterminate`).

  ## Storage

  Counters live in an `:ets` table keyed on
  `{namespace, key}`. Reads are lock-free; writes use
  `:ets.update_counter/3` so concurrent telemetry callbacks
  don't serialise on a single GenServer.

  ## Time window

  The endpoint advertises a `window_seconds` parameter. Today
  the counters are monotonic since `init/0` — the window is
  used as a hint only. A future revision can track per-bucket
  histograms.

  ## Lifecycle

  * `init/0` creates the ETS table + attaches every telemetry
    handler. Idempotent. Called from `ExDns.Application.start/2`
    (and lazily from `snapshot/1` in case the supervisor isn't
    running, e.g. tests).
  * `clear/0` drops every counter. Test helper.
  """

  @table :ex_dns_api_metrics_counters
  @handler_id "ex_dns_api_metrics_counters"

  @doc "Initialise the counter table + attach telemetry. Idempotent."
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

      _ ->
        :ok
    end

    :telemetry.detach(@handler_id)

    :telemetry.attach_many(
      @handler_id,
      [
        [:ex_dns, :query, :start],
        [:ex_dns, :rrl, :drop],
        [:ex_dns, :cache, :hit],
        [:ex_dns, :cache, :miss],
        [:ex_dns, :dnssec, :validate, :stop]
      ],
      &__MODULE__.handle_event/4,
      %{}
    )

    :ok
  end

  @doc false
  def handle_event([:ex_dns, :query, :start], _, metadata, _) do
    qtype = metadata[:qtype] || metadata["qtype"] || :unknown
    bump({:queries, to_string(qtype)})
  end

  def handle_event([:ex_dns, :rrl, :drop], _, _metadata, _) do
    bump({:rrl_drops, :total})
  end

  def handle_event([:ex_dns, :cache, :hit], _, _metadata, _) do
    bump({:cache_hits, :hit})
  end

  def handle_event([:ex_dns, :cache, :miss], _, _metadata, _) do
    bump({:cache_hits, :miss})
  end

  def handle_event([:ex_dns, :dnssec, :validate, :stop], _, metadata, _) do
    status = metadata[:status] || :unknown
    bump({:dnssec, to_string(status)})
  end

  defp bump(key) do
    init()
    :ets.update_counter(@table, key, {2, 1}, {key, 0})
    :ok
  end

  @doc """
  Return a snapshot of the counters in the shape the API
  exposes. `window_seconds` is echoed back; values are
  monotonic-since-init (we don't track windowed histograms).
  """
  @spec snapshot(pos_integer()) :: map()
  def snapshot(window_seconds \\ 60) do
    init()

    %{
      "window_seconds" => window_seconds,
      "queries" => bucketed(:queries),
      "rrl_drops" => total(:rrl_drops),
      "cache_hits" => bucketed(:cache_hits, %{"hit" => 0, "miss" => 0}),
      "dnssec" => bucketed(:dnssec)
    }
  end

  @doc "Reset the counters table. Test helper."
  @spec clear() :: :ok
  def clear do
    init()
    :ets.delete_all_objects(@table)
    :ok
  end

  defp bucketed(namespace, default \\ %{}) do
    init()

    @table
    |> :ets.tab2list()
    |> Enum.reduce(default, fn
      {{^namespace, key}, value}, acc -> Map.put(acc, to_string(key), value)
      _, acc -> acc
    end)
  end

  defp total(namespace) do
    bucketed(namespace) |> Map.values() |> Enum.sum()
  end
end
