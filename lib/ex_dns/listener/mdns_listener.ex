defmodule ExDns.Listener.MDNS do
  @moduledoc """
  Multicast DNS responder (RFC 6762).

  Listens on UDP port 5353 with the mDNS IPv4 multicast group
  `224.0.0.251` joined. Co-exists with the OS's mDNSResponder (macOS,
  systemd-resolved, Avahi) by setting `SO_REUSEADDR` and
  `SO_REUSEPORT` on the listening socket so multiple processes can
  receive the same multicast packets.

  Inbound queries are handed to `ExDns.Resolver.MDNS`, which only
  answers for names ending in `.local`. The response routing follows
  RFC 6762 §6:

  * If the question's QU bit (top bit of QCLASS) is set, the response
    is sent **unicast** back to the querier.
  * Otherwise the response is sent **multicast** to the group.

  ## Configuration

  Enable with:

      config :ex_dns, mdns: [enabled: true]

  Optional keys:

  * `:port` (default 5353)
  * `:multicast_ip` (default `{224, 0, 0, 251}`)
  * `:interface` (default `{0, 0, 0, 0}` — bind to any local IPv4)
  * `:multicast_ttl` (default 255 per RFC 6762 §11)
  * `:multicast_loop` (default `false` — don't receive our own packets)

  Note: when running on macOS the OS's `mDNSResponder` will *also*
  receive (and may answer) the same queries. For controlled testing,
  send queries from a process that uses our listener's address as the
  unicast target via `+noedns` style direct UDP, bypassing
  `mDNSResponder`.

  """

  use GenServer
  require Logger

  alias ExDns.Message
  alias ExDns.Resolver.MDNS, as: Resolver

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

  @impl true
  def init(options) do
    port = Keyword.get(options, :port, 5353)
    multicast_ip = Keyword.get(options, :multicast_ip, {224, 0, 0, 251})
    interface = Keyword.get(options, :interface, {0, 0, 0, 0})
    multicast_ttl = Keyword.get(options, :multicast_ttl, 255)
    multicast_loop = Keyword.get(options, :multicast_loop, false)

    udp_options = [
      :binary,
      :inet,
      {:active, true},
      {:reuseaddr, true},
      {:multicast_ttl, multicast_ttl},
      {:multicast_loop, multicast_loop},
      {:add_membership, {multicast_ip, interface}},
      {:ip, interface}
    ]

    udp_options = udp_options ++ reuseport_options()

    case :gen_udp.open(port, udp_options) do
      {:ok, socket} ->
        Logger.info(
          "ExDns.Listener.MDNS: bound to #{:inet_parse.ntoa(interface)}:#{port}, " <>
            "joined #{:inet_parse.ntoa(multicast_ip)}"
        )

        {:ok,
         %{
           socket: socket,
           port: port,
           multicast_ip: multicast_ip,
           interface: interface
         }}

      {:error, reason} ->
        Logger.error("ExDns.Listener.MDNS: could not bind: #{inspect(reason)}")
        {:stop, reason}
    end
  end

  # Some OSes also accept the (modern) `:reuseport` option; on macOS
  # the older raw socket option must be set instead. Use whichever the
  # current Erlang exposes, falling back to nothing if neither.
  defp reuseport_options do
    cond do
      function_exported?(:inet, :setopts, 2) ->
        case :os.type() do
          {:unix, :darwin} ->
            # SOL_SOCKET = 0xffff, SO_REUSEPORT = 0x0200 on macOS.
            [{:raw, 0xFFFF, 0x0200, <<1::native-size(32)>>}]

          {:unix, :linux} ->
            # SOL_SOCKET = 1, SO_REUSEPORT = 15 on Linux.
            [{:raw, 1, 15, <<1::native-size(32)>>}]

          _ ->
            []
        end

      true ->
        []
    end
  end

  @impl true
  def handle_info({:udp, socket, source_ip, source_port, packet}, state) do
    case Message.decode(packet) do
      {:ok, query} ->
        request =
          ExDns.Request.new(query,
            source_ip: source_ip,
            source_port: source_port,
            transport: :mdns
          )

        case Resolver.resolve(request) do
          :no_answer ->
            :ok

          {:unicast, response} ->
            send_response(socket, source_ip, source_port, response, :unicast, state)

          {:multicast, response} ->
            send_response(socket, source_ip, source_port, response, :multicast, state)
        end

      {:error, _} ->
        # mDNS sees a lot of malformed/foreign packets; ignore quietly.
        :ok
      end

    {:noreply, state}
  end

  def handle_info(_other, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{socket: socket}) do
    :gen_udp.close(socket)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  defp send_response(socket, source_ip, source_port, response, mode, state) do
    bytes = Message.encode(response)

    {target_ip, target_port} =
      case mode do
        :unicast -> {source_ip, source_port}
        :multicast -> {state.multicast_ip, state.port}
      end

    case :gen_udp.send(socket, target_ip, target_port, bytes) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.error(
          "ExDns.Listener.MDNS: send to #{:inet_parse.ntoa(target_ip)}:#{target_port} " <>
            "failed: #{inspect(reason)}"
        )
    end
  end
end
