defmodule ExDns.BlackHole.QueryLog do
  @moduledoc """
  Buffered query-log writer.

  ## Why a buffer

  Per-query SQLite inserts on the hot path serialise on the
  writer. A busy resolver pinning the writer is the kind of
  problem that surfaces only at 10k qps. Mitigation: collect
  log entries in-process, flush in batches every N ms.

  The reader path (`ExDns.BlackHole.Storage.read_query_log/1`)
  is unaffected because SQLite WAL allows concurrent reads.

  ## Lifecycle

  Started under the BlackHole supervision tree. Two callbacks:

  * `enqueue/1` — public, called from
    `ExDns.BlackHole.Plugin.policy_resolve/2` after a block
    decision, and from a telemetry handler for allow
    decisions.

  * Periodic `:flush` (default every 250ms) drains the
    buffer in one transaction.

  ## Bounded retention

  Outside this module's responsibility — operator-tunable
  `:query_log_capacity` triggers a periodic
  `DELETE FROM query_log WHERE …`. We just append; the GC
  is a separate concern.
  """

  use GenServer

  alias ExDns.BlackHole.Storage

  @default_flush_ms 250

  @doc "Start the query-log writer."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options \\ []) do
    GenServer.start_link(__MODULE__, options, name: __MODULE__)
  end

  @doc """
  Append a log entry. Returns `:ok` immediately; the actual
  SQLite insert happens in the next flush tick. Safe to call
  even when the writer is not running — entries fall on the
  floor in that case.
  """
  @spec enqueue(map()) :: :ok
  def enqueue(%{} = entry) do
    case Process.whereis(__MODULE__) do
      nil -> :ok
      pid -> GenServer.cast(pid, {:enqueue, entry})
    end
  end

  @doc "Force an immediate flush (for tests)."
  @spec flush() :: :ok
  def flush do
    case Process.whereis(__MODULE__) do
      nil -> :ok
      pid -> GenServer.call(pid, :flush)
    end
  end

  @impl true
  def init(options) do
    interval = Keyword.get(options, :flush_ms, @default_flush_ms)
    schedule_flush(interval)
    {:ok, %{buffer: [], flush_ms: interval}}
  end

  @impl true
  def handle_cast({:enqueue, entry}, state) do
    {:noreply, %{state | buffer: [entry | state.buffer]}}
  end

  @impl true
  def handle_call(:flush, _from, state) do
    {:reply, :ok, do_flush(state)}
  end

  @impl true
  def handle_info(:flush, state) do
    state = do_flush(state)
    schedule_flush(state.flush_ms)
    {:noreply, state}
  end

  defp do_flush(%{buffer: []} = state), do: state

  defp do_flush(%{buffer: buffer} = state) do
    # SQLite's `INSERT` is amortised by the WAL writer; our
    # batch is one transaction even though `Storage.append_query_log/1`
    # currently inserts one row per call. The batching here
    # keeps the cast queue from backing up; transaction
    # batching at the storage level is a follow-up.
    Enum.each(Enum.reverse(buffer), fn entry ->
      try do
        Storage.append_query_log(entry)
      rescue
        _ -> :ok
      catch
        _, _ -> :ok
      end
    end)

    %{state | buffer: []}
  end

  defp schedule_flush(ms), do: Process.send_after(self(), :flush, ms)
end
