defmodule ExDns.Zone.Snapshot.Writer do
  @moduledoc """
  Debounced background writer that persists zone state to disk
  whenever runtime mutations occur.

  ## Behaviour

  Calling `request/0` schedules a snapshot write after a short
  idle delay (default 500ms). Subsequent `request/0` calls
  inside the window slide the deadline — bursts of mutations
  (e.g. dynamic UPDATE applying many records, or a large
  AXFR landing) coalesce into a single disk write.

  Disabled by default. Enable via:

      config :ex_dns, :zone_snapshot,
        enabled: true,
        path: "/var/lib/exdns/snapshot.bin",
        debounce_ms: 500

  ## Telemetry

  * `[:ex_dns, :zone_snapshot, :write]` — fired after each
    successful write with `%{zones, bytes}` measurements and
    metadata `%{path}`.
  * `[:ex_dns, :zone_snapshot, :error]` — fired when the write
    fails with metadata `%{reason, path}`.
  """

  use GenServer

  alias ExDns.Zone.Snapshot

  require Logger

  @default_debounce_ms 500

  @doc "Start the writer. Used by `ExDns.Application.start/2`."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options \\ []) do
    GenServer.start_link(__MODULE__, options, name: __MODULE__)
  end

  @doc """
  Request a snapshot write. Coalesced with any other request
  inside the debounce window.

  Returns `:ok` synchronously even when the writer is not
  running — runtime callers can use it unconditionally without
  caring whether snapshotting is enabled.
  """
  @spec request() :: :ok
  def request do
    case Process.whereis(__MODULE__) do
      nil ->
        :ok

      pid ->
        GenServer.cast(pid, :request)
    end
  end

  @doc "Force an immediate write, bypassing the debounce. Used by tests + admin tools."
  @spec write_now() :: {:ok, map()} | {:error, term()}
  def write_now do
    case Process.whereis(__MODULE__) do
      nil -> Snapshot.write(Snapshot.configured_path())
      pid -> GenServer.call(pid, :write_now)
    end
  end

  @impl true
  def init(options) do
    state = %{
      path: Keyword.get_lazy(options, :path, &Snapshot.configured_path/0),
      debounce_ms: Keyword.get(options, :debounce_ms, configured_debounce_ms()),
      timer: nil
    }

    {:ok, state}
  end

  @impl true
  def handle_cast(:request, state) do
    {:noreply, schedule(state)}
  end

  @impl true
  def handle_call(:write_now, _from, state) do
    cancel(state.timer)
    result = do_write(state.path)
    {:reply, result, %{state | timer: nil}}
  end

  @impl true
  def handle_info(:write_due, state) do
    _ = do_write(state.path)
    {:noreply, %{state | timer: nil}}
  end

  defp schedule(%{timer: timer, debounce_ms: ms} = state) do
    cancel(timer)
    new_timer = Process.send_after(self(), :write_due, ms)
    %{state | timer: new_timer}
  end

  defp cancel(nil), do: :ok
  defp cancel(ref) when is_reference(ref), do: Process.cancel_timer(ref)

  defp do_write(path) do
    case Snapshot.write(path) do
      {:ok, %{zones: zones, bytes: bytes}} = ok ->
        :telemetry.execute(
          [:ex_dns, :zone_snapshot, :write],
          %{zones: zones, bytes: bytes},
          %{path: path}
        )

        ok

      {:error, reason} = err ->
        Logger.warning("ExDns.Zone.Snapshot.Writer: write to #{path} failed: #{inspect(reason)}")

        :telemetry.execute(
          [:ex_dns, :zone_snapshot, :error],
          %{count: 1},
          %{reason: reason, path: path}
        )

        err
    end
  end

  defp configured_debounce_ms do
    Application.get_env(:ex_dns, :zone_snapshot, [])
    |> Keyword.get(:debounce_ms, @default_debounce_ms)
  end
end
