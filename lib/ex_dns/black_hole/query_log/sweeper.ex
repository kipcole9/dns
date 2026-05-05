defmodule ExDns.BlackHole.QueryLog.Sweeper do
  @moduledoc """
  Periodic retention sweeper for the BlackHole query log.

  ## Why

  The query log table is append-heavy. Without a sweeper it
  grows monotonically. The sweeper runs on a configurable
  interval and applies one of two retention policies:

  * **By count** — keep the most-recent N rows. Implemented
    by deleting everything older than the timestamp of the
    Nth-newest row.
  * **By age** — keep rows newer than the configured wall
    clock. Implemented by `DELETE FROM query_log WHERE
    ts_ns < ?`.

  The two are combined with an OR — the sweeper enforces
  whichever cap is tighter.

  ## Configuration

      config :ex_dns, :black_hole,
        query_log_capacity: 100_000,        # max rows
        query_log_max_age_seconds: 604_800, # 7 days
        query_log_sweep_interval_ms: 60_000

  Either cap can be `nil` to disable that side.
  """

  use GenServer

  alias ExDns.BlackHole.Storage

  require Logger

  @default_interval_ms 60_000
  @default_capacity 100_000

  @doc "Start the sweeper."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options \\ []) do
    GenServer.start_link(__MODULE__, options, name: __MODULE__)
  end

  @doc "Force an immediate sweep (for tests)."
  @spec sweep_now() :: :ok
  def sweep_now do
    case Process.whereis(__MODULE__) do
      nil -> :ok
      pid -> GenServer.cast(pid, :sweep_now)
    end
  end

  @impl true
  def init(_options) do
    state = %{
      interval_ms: configured_interval(),
      capacity: configured_capacity(),
      max_age_s: configured_max_age()
    }

    schedule(state.interval_ms)
    {:ok, state}
  end

  @impl true
  def handle_cast(:sweep_now, state) do
    do_sweep(state)
    {:noreply, state}
  end

  @impl true
  def handle_info(:sweep, state) do
    do_sweep(state)
    schedule(state.interval_ms)
    {:noreply, state}
  end

  defp schedule(ms), do: Process.send_after(self(), :sweep, ms)

  defp do_sweep(%{capacity: nil, max_age_s: nil}), do: :ok

  defp do_sweep(state) do
    cutoff_age = age_cutoff(state.max_age_s)
    cutoff_count = count_cutoff(state.capacity)

    cutoff =
      cond do
        is_nil(cutoff_age) and is_nil(cutoff_count) -> nil
        is_nil(cutoff_age) -> cutoff_count
        is_nil(cutoff_count) -> cutoff_age
        true -> max(cutoff_age, cutoff_count)
      end

    case cutoff do
      nil -> :ok
      ts_ns -> delete_older_than(ts_ns)
    end
  end

  defp age_cutoff(nil), do: nil

  defp age_cutoff(seconds) when is_integer(seconds) and seconds > 0 do
    System.os_time(:nanosecond) - seconds * 1_000_000_000
  end

  defp age_cutoff(_), do: nil

  defp count_cutoff(nil), do: nil

  defp count_cutoff(capacity) when is_integer(capacity) and capacity > 0 do
    # Read one page at the configured capacity; the cursor
    # returned (the timestamp of the (capacity+1)th row, if any)
    # is the cutoff. Below this row count, no cutoff applies.
    case Storage.read_query_log(%{limit: capacity}) do
      %{next_cursor: nil} -> nil
      %{next_cursor: cursor} when is_integer(cursor) -> cursor
      _ -> nil
    end
  end

  defp count_cutoff(_), do: nil

  defp delete_older_than(ts_ns) do
    try do
      Storage.delete_query_log_before(ts_ns)
      Logger.debug("BlackHole sweeper: deleted rows older than ts_ns=#{ts_ns}")
    rescue
      e ->
        Logger.warning("BlackHole sweeper failed: #{inspect(e)}")
    catch
      _, reason ->
        Logger.warning("BlackHole sweeper failed: #{inspect(reason)}")
    end

    :ok
  end

  defp configured_interval do
    Application.get_env(:ex_dns, :black_hole, [])
    |> Keyword.get(:query_log_sweep_interval_ms, @default_interval_ms)
  end

  defp configured_capacity do
    Application.get_env(:ex_dns, :black_hole, [])
    |> Keyword.get(:query_log_capacity, @default_capacity)
  end

  defp configured_max_age do
    Application.get_env(:ex_dns, :black_hole, [])
    |> Keyword.get(:query_log_max_age_seconds, nil)
  end
end
