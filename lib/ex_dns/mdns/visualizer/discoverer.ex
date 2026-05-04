defmodule ExDns.MDNS.Visualizer.Discoverer do
  @moduledoc """
  Periodically browses the local mDNS network and accumulates the
  observed service registry.

  Architecture mirrors the data layer of the
  `Color.Palette.Visualizer` pattern: a small GenServer is the source
  of truth, the HTTP layer reads its state, and the rendering layer
  stays pure (no I/O).

  Every `:interval` milliseconds (default 5_000) the discoverer:

  1. Opens an ephemeral UDP socket and joins (or unicasts to)
     `224.0.0.251:5353`.
  2. Sends a PTR query for `_services._dns-sd._udp.local` (the
     meta-service browser) and a PTR query for each service type it
     has previously observed.
  3. Listens for `:listen_window` ms, decoding every reply.
  4. Folds the observed PTR / SRV / TXT / A / AAAA records into the
     accumulated state.
  5. Closes the socket.

  State is exposed via `snapshot/0`, which the Plug router reads to
  render each page.

  ## Options

  * `:interval` — refresh period in ms (default 5_000).
  * `:listen_window` — how long to wait for replies per cycle in ms
    (default 1_000).
  * `:multicast_ip` — destination IP for queries
    (default `{224, 0, 0, 251}`).
  * `:port` — destination port (default 5353).

  """

  use GenServer

  require Logger

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resource.{A, AAAA, PTR, SRV, TXT}

  @default_interval 5_000
  @default_listen_window 1_000
  @default_multicast_ip {224, 0, 0, 251}
  @default_port 5353
  @meta_browser "_services._dns-sd._udp.local"

  @doc false
  def child_spec(options) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [options]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end

  def start_link(options \\ []) do
    GenServer.start_link(__MODULE__, options, name: __MODULE__)
  end

  @doc """
  Returns the current accumulated view of advertised services.

  ### Returns

  A map shaped:

      %{
        last_refresh: ~U[2026-05-05 …],
        last_refresh_monotonic_ms: …,
        cycles: <count>,
        types: ["_http._tcp.local", "_workstation._tcp.local", …],
        services: %{
          "_http._tcp.local" => %{
            "MyPrinter._http._tcp.local" => %{
              srv: %ExDns.Resource.SRV{...} | nil,
              txt: %ExDns.Resource.TXT{...} | nil,
              addresses: [{a, b, c, d} | {…ipv6…}, …]
            },
            …
          },
          …
        }
      }

  """
  @spec snapshot() :: map()
  def snapshot do
    case Process.whereis(__MODULE__) do
      nil ->
        %{last_refresh: nil, cycles: 0, types: [], services: %{}}

      _pid ->
        GenServer.call(__MODULE__, :snapshot)
    end
  end

  @doc "Forces an immediate refresh cycle and returns once it completes."
  @spec refresh_now() :: :ok
  def refresh_now do
    GenServer.call(__MODULE__, :refresh_now, 30_000)
  end

  # ----- GenServer ----------------------------------------------------

  @impl true
  def init(options) do
    state = %{
      interval: Keyword.get(options, :interval, @default_interval),
      listen_window: Keyword.get(options, :listen_window, @default_listen_window),
      multicast_ip: Keyword.get(options, :multicast_ip, @default_multicast_ip),
      port: Keyword.get(options, :port, @default_port),
      cycles: 0,
      last_refresh: nil,
      last_refresh_monotonic_ms: nil,
      types: MapSet.new(),
      services: %{}
    }

    send(self(), :tick)
    {:ok, state}
  end

  @impl true
  def handle_info(:tick, state) do
    state = run_cycle(state)
    Process.send_after(self(), :tick, state.interval)
    {:noreply, state}
  end

  def handle_info(_other, state), do: {:noreply, state}

  @impl true
  def handle_call(:snapshot, _from, state) do
    {:reply, public_snapshot(state), state}
  end

  def handle_call(:refresh_now, _from, state) do
    state = run_cycle(state)
    {:reply, :ok, state}
  end

  defp public_snapshot(state) do
    %{
      last_refresh: state.last_refresh,
      last_refresh_monotonic_ms: state.last_refresh_monotonic_ms,
      cycles: state.cycles,
      types: state.types |> MapSet.to_list() |> Enum.sort(),
      services: state.services
    }
  end

  # ----- discovery ----------------------------------------------------

  # Maximum passes per cycle. mDNS discovery is naturally tiered
  # (types → instances → SRV/TXT → A/AAAA), so we keep iterating
  # until the state stops changing or we hit this ceiling.
  @max_passes 4

  defp run_cycle(state) do
    socket_options = open_socket_options(state.multicast_ip)

    case :gen_udp.open(0, socket_options) do
      {:ok, socket} ->
        try do
          state = run_passes(socket, state, @max_passes)

          %{
            state
            | cycles: state.cycles + 1,
              last_refresh: DateTime.utc_now(),
              last_refresh_monotonic_ms: System.monotonic_time(:millisecond)
          }
        after
          :gen_udp.close(socket)
        end

      {:error, reason} ->
        Logger.warning("ExDns.MDNS.Visualizer.Discoverer: socket open failed: #{inspect(reason)}")
        state
    end
  end

  defp run_passes(_socket, state, 0), do: state

  defp run_passes(socket, state, remaining) do
    snapshot_before = {state.types, state.services}
    send_browse_queries(socket, state)
    received = drain(socket, state.listen_window)
    state = fold_records(state, received)

    if {state.types, state.services} == snapshot_before do
      state
    else
      run_passes(socket, state, remaining - 1)
    end
  end

  defp open_socket_options({a, _, _, _}) when a in 224..239 do
    [
      :binary,
      {:active, false},
      {:multicast_ttl, 255},
      {:multicast_loop, true},
      {:add_membership, {{a, 0, 0, 251}, {0, 0, 0, 0}}}
    ]
  end

  defp open_socket_options(_unicast) do
    [:binary, {:active, false}]
  end

  defp send_browse_queries(socket, state) do
    meta = build_query(@meta_browser, :ptr)
    _ = :gen_udp.send(socket, state.multicast_ip, state.port, meta)

    # Re-query each known service type so we pick up new instances.
    Enum.each(state.types, fn type ->
      bytes = build_query(type, :ptr)
      :gen_udp.send(socket, state.multicast_ip, state.port, bytes)
    end)

    # For every known instance, ask for its SRV and TXT so we can
    # render port/target/text fields.
    for {_type, instances} <- state.services,
        {instance, _details} <- instances do
      for qtype <- [:srv, :txt] do
        bytes = build_query(instance, qtype)
        :gen_udp.send(socket, state.multicast_ip, state.port, bytes)
      end
    end

    # For every SRV target we already know, ask for its A/AAAA so
    # the address columns populate.
    for {_type, instances} <- state.services,
        {_instance, %{srv: %ExDns.Resource.SRV{target: target}}} <- instances,
        is_binary(target) do
      for qtype <- [:a, :aaaa] do
        bytes = build_query(target, qtype)
        :gen_udp.send(socket, state.multicast_ip, state.port, bytes)
      end
    end
  end

  defp build_query(name, qtype) do
    header = %Header{
      id: 0,
      qr: 0,
      oc: 0,
      aa: 0,
      tc: 0,
      rd: 0,
      ra: 0,
      ad: 0,
      cd: 0,
      rc: 0,
      qc: 1,
      anc: 0,
      auc: 0,
      adc: 0
    }

    question = %Question{
      host: name,
      type: qtype,
      class: :in,
      # QU = unicast response wanted, so replies come back to our
      # ephemeral source port.
      unicast_response: true
    }

    %Message{
      header: header,
      question: question,
      answer: [],
      authority: [],
      additional: []
    }
    |> Message.encode()
  end

  defp drain(socket, window_ms) do
    deadline = System.monotonic_time(:millisecond) + window_ms
    drain(socket, deadline, [])
  end

  defp drain(socket, deadline, acc) do
    remaining = max(0, deadline - System.monotonic_time(:millisecond))

    if remaining == 0 do
      acc
    else
      case :gen_udp.recv(socket, 0, remaining) do
        {:ok, {ip, _port, packet}} ->
          case Message.decode(packet) do
            {:ok, message} -> drain(socket, deadline, [{ip, message} | acc])
            _ -> drain(socket, deadline, acc)
          end

        {:error, :timeout} ->
          acc

        {:error, _other} ->
          acc
      end
    end
  end

  # ----- folding ------------------------------------------------------

  defp fold_records(state, received) do
    Enum.reduce(received, state, fn {ip, message}, acc ->
      records = (message.answer || []) ++ (message.authority || []) ++ (message.additional || [])
      Enum.reduce(records, acc, fn record, acc -> fold_record(acc, record, ip) end)
    end)
  end

  # PTR at the meta browser → register a service type we should query for.
  defp fold_record(state, %PTR{name: @meta_browser, pointer: type}, _ip) do
    %{state | types: MapSet.put(state.types, normalize(type))}
  end

  # PTR at a service type → register an instance under that type.
  defp fold_record(state, %PTR{name: type, pointer: instance}, _ip) do
    type = normalize(type)
    instance = normalize(instance)

    state
    |> ensure_type_bucket(type)
    |> update_in([:services, type], fn instances ->
      Map.put_new(instances, instance, blank_instance())
    end)
    |> add_known_type(type)
  end

  defp fold_record(state, %SRV{} = srv, _ip) do
    instance = normalize(srv.name)
    type = type_from_instance(instance)

    state
    |> ensure_type_bucket(type)
    |> update_in([:services, type, instance], fn details ->
      details = details || blank_instance()
      %{details | srv: srv}
    end)
    |> add_known_type(type)
  end

  defp fold_record(state, %TXT{} = txt, _ip) do
    instance = normalize(txt.name)
    type = type_from_instance(instance)

    state
    |> ensure_type_bucket(type)
    |> update_in([:services, type, instance], fn details ->
      details = details || blank_instance()
      %{details | txt: txt}
    end)
    |> add_known_type(type)
  end

  defp fold_record(state, %A{} = a, _ip) do
    fold_address(state, normalize(a.name), a.ipv4)
  end

  defp fold_record(state, %AAAA{} = aaaa, _ip) do
    fold_address(state, normalize(aaaa.name), aaaa.ipv6)
  end

  defp fold_record(state, _other, _ip), do: state

  # When we get an A/AAAA, attach it to every instance whose SRV
  # target matches the record's owner name.
  defp fold_address(state, owner, address) do
    services =
      Enum.into(state.services, %{}, fn {type, instances} ->
        instances =
          Enum.into(instances, %{}, fn {instance, details} ->
            if details.srv && normalize(details.srv.target) == owner do
              addresses = (details.addresses ++ [address]) |> Enum.uniq()
              {instance, %{details | addresses: addresses}}
            else
              {instance, details}
            end
          end)

        {type, instances}
      end)

    %{state | services: services}
  end

  defp ensure_type_bucket(state, type) do
    if Map.has_key?(state.services, type) do
      state
    else
      put_in(state, [:services, type], %{})
    end
  end

  defp add_known_type(state, type) do
    %{state | types: MapSet.put(state.types, type)}
  end

  defp blank_instance, do: %{srv: nil, txt: nil, addresses: []}

  defp type_from_instance(instance) do
    case String.split(instance, ".", parts: 2) do
      [_first, rest] -> rest
      [only] -> only
    end
  end

  defp normalize(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end

  defp normalize(other), do: other
end
