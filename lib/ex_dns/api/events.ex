defmodule ExDns.API.Events do
  @moduledoc """
  Server-Sent Events broker for the `/api/v1/events` stream.

  ## Behaviour

  A small `Registry` of subscribers — typically the connected
  HTTP request processes serving the SSE endpoint. Telemetry
  events fired by the server elsewhere (zone reloads,
  secondary state transitions, plugin registry changes,
  DNSSEC rollover) are translated to SSE events and broadcast
  to every subscriber.

  ## SSE wire format

  Each event is rendered per RFC 8895 / WHATWG html-living-spec
  §SSE:

  ```
  event: <type>\\n
  data: <json>\\n
  \\n
  ```

  Subscribers consume the messages they receive and write the
  bytes to the client connection.

  ## Public surface

  * `start_link/1` — start the broker (one per node).
  * `subscribe/1` — register `pid` as a subscriber. Returns
    `:ok`. The pid receives `{:exdns_event, type, payload_map}`
    messages.
  * `broadcast/2` — fire an event to every subscriber.
  * `attach_telemetry/0` — wires the bundled telemetry
    handlers; called from `Application.start/2`.

  Each subscriber is monitored. When the subscriber dies the
  registry entry is cleaned up automatically.
  """

  use GenServer

  require Logger

  @doc "Start the broker. Idempotent under a stable name."
  def start_link(_options \\ []) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  @doc """
  Subscribe `pid` (defaults to self) to receive
  `{:exdns_event, type, payload}` messages.
  """
  @spec subscribe(pid()) :: :ok
  def subscribe(pid \\ self()) when is_pid(pid) do
    GenServer.cast(__MODULE__, {:subscribe, pid})
  end

  @doc "Number of currently subscribed pids. Used by tests."
  @spec subscribers() :: non_neg_integer()
  def subscribers do
    GenServer.call(__MODULE__, :subscribers)
  end

  @doc """
  Broadcast an event to every subscriber. `type` is a short
  atom (mirrored as a string in the SSE `event:` field);
  `payload` is a JSON-shaped map.
  """
  @spec broadcast(atom(), map()) :: :ok
  def broadcast(type, payload) when is_atom(type) and is_map(payload) do
    GenServer.cast(__MODULE__, {:broadcast, type, payload})
  end

  @doc """
  Render `{type, payload}` as a single SSE wire fragment. Pure;
  used by the HTTP handler in `ExDns.API.SSE`.
  """
  @spec render_sse(atom(), map()) :: iodata()
  def render_sse(type, payload) when is_atom(type) and is_map(payload) do
    json = payload |> :json.encode() |> IO.iodata_to_binary()
    ["event: ", Atom.to_string(type), "\n", "data: ", json, "\n\n"]
  end

  @doc "Attach the bundled telemetry handlers to the broker."
  @spec attach_telemetry() :: :ok | {:error, term()}
  def attach_telemetry do
    handler_id = "ex_dns_api_events"
    :telemetry.detach(handler_id)

    :telemetry.attach_many(
      handler_id,
      [
        [:ex_dns, :secondary, :loaded],
        [:ex_dns, :secondary, :transfer_failed],
        [:ex_dns, :catalog, :poll, :stop],
        [:ex_dns, :rpz, :match],
        [:ex_dns, :zone_snapshot, :write]
      ],
      &__MODULE__.handle_telemetry/4,
      %{}
    )
  end

  @doc false
  def handle_telemetry([:ex_dns, :secondary, :loaded], _, metadata, _) do
    broadcast(:"secondary.loaded", to_string_map(metadata))
  end

  def handle_telemetry([:ex_dns, :secondary, :transfer_failed], _, metadata, _) do
    broadcast(:"secondary.transfer_failed", to_string_map(metadata))
  end

  def handle_telemetry([:ex_dns, :catalog, :poll, :stop], measurements, metadata, _) do
    payload =
      metadata
      |> to_string_map()
      |> Map.put("members", measurements[:members] || 0)

    broadcast(:"catalog.polled", payload)
  end

  def handle_telemetry([:ex_dns, :rpz, :match], _, metadata, _) do
    broadcast(:"rpz.match", to_string_map(metadata))
  end

  def handle_telemetry([:ex_dns, :zone_snapshot, :write], measurements, metadata, _) do
    payload =
      metadata
      |> to_string_map()
      |> Map.put("zones", measurements[:zones])
      |> Map.put("bytes", measurements[:bytes])

    broadcast(:"zone_snapshot.written", payload)
  end

  defp to_string_map(map) when is_map(map) do
    Enum.into(map, %{}, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), stringify(v)}
      {k, v} -> {to_string(k), stringify(v)}
    end)
  end

  defp stringify(v) when is_atom(v) and not is_boolean(v) and not is_nil(v),
    do: Atom.to_string(v)

  defp stringify(v) when is_tuple(v), do: inspect(v)
  defp stringify(v), do: v

  # ----- GenServer callbacks ---------------------------------------

  @impl true
  def init(_) do
    {:ok, %{subscribers: %{}}}
  end

  @impl true
  def handle_cast({:subscribe, pid}, state) do
    if Map.has_key?(state.subscribers, pid) do
      {:noreply, state}
    else
      ref = Process.monitor(pid)
      {:noreply, %{state | subscribers: Map.put(state.subscribers, pid, ref)}}
    end
  end

  def handle_cast({:broadcast, type, payload}, state) do
    Enum.each(state.subscribers, fn {pid, _ref} ->
      send(pid, {:exdns_event, type, payload})
    end)

    {:noreply, state}
  end

  @impl true
  def handle_call(:subscribers, _from, state) do
    {:reply, map_size(state.subscribers), state}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    {:noreply, %{state | subscribers: Map.delete(state.subscribers, pid)}}
  end

  def handle_info(_, state), do: {:noreply, state}
end
