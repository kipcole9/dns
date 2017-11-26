defmodule ExDns.Listener.UDP do
  use GenServer
  require Logger

  alias ExDns.Prometheus.Instrumenter
  alias ExDns.Resolver

  @read_packets 1000
  @active       100

  @doc """
  Resolves the DNS request.

  This function checks out a worker from the pool and
  `GenServer.cast`s it to perform the resolution and
  return a result to the requester.

  If a timeout occurs trying to check out a worker it
  means there are no more workers and we will drop the
  resolver request.
  """
  def resolve(address, port, socket, bin, state) do
    case get_worker() do
      {:ok, worker} when is_pid(worker) ->
        try do
          GenServer.cast(worker, {:udp_query, address, port, socket, bin})
        after
          :poolboy.checkin(Resolver.Supervisor.pool_name, worker)
          {:noreply, state}
        end
      {:error, {message, _pool_status}} = error ->
        Logger.error message
        Instrumenter.packet_dropped(error)
        {:noreply, state}
    end
  end

  def ping do
    {:ok, socket} = :gen_udp.open(0)
    {:ok, address} = :inet_parse.address('127.0.0.1')
    :gen_udp.send(socket, address, 8000, "This is a test")
    :gen_udp.close(socket)
  end

  def start_link(%{inet_family: inet_family, address: address, port: port,
        socket_options: socket_options} = args) do
    name = Map.get(args, :name) || name_from_module(__MODULE__, inet_family)
    GenServer.start_link(__MODULE__, [inet_family, address, port, socket_options], [name: name])
  end

  def init([inet_family, address, port, nil]) do
    init([inet_family, address, port, []])
  end

  def init([inet_family, address, port, socket_options]) do
    Logger.info "Starting UDP server for #{inspect inet_family} on address " <>
                "#{:inet_parse.ntoa(address)} and port #{inspect port} with options " <>
                "#{inspect socket_options}"

    {:ok, socket} = open_socket(inet_family, address, port, socket_options)
    {:ok, %{address: address, port: port, socket: socket}}
  end

  @doc """
  Receives the incoming UDP message and dispatches a worker to
  process is.

  Since this handler operates in a serial fashion it needs to
  hand off to a worker as fast as possible so it can process
  the next message.

  The format of the msssage is defined by the `:inet` module.
  """
  def handle_info({:udp, socket, host, port, bin}, state) do
    response = resolve(host, port, socket, bin, state)
    :inet.setopts(Map.get(state, :socket), active: @active)
    {:noreply, state}
  end

  def handle_info(:timeout, state) do
    Logger.error("UDP instance timed out")
    {:noreply, state}
  end

  def handle_info(_message, state) do
    {:noreply, state}
  end

  def handle_call(_request, _from, state) do
    {:reply, :ok, state}
  end

  def handle_cast(_message, state) do
    {:noreply, state}
  end

  def terminate(_reason, _state) do
    :ok
  end

  def code_change(_previous_version, state, _extra) do
    {:ok, state}
  end

  def get_worker do
    try do
      pool_name = Resolver.Supervisor.pool_name
      pid = :poolboy.checkout(pool_name, true, ExDns.checkout_timeout)
      Instrumenter.resolvers_checked_out(:poolboy.status(pool_name))
      {:ok, pid}
    catch :exit, _error ->
      {:error, {"No more workers are available. Packet dropped", Resolver.Supervisor.pool_status}}
    end
  end

  defp open_socket(inet_family, address, port, socket_options) do
    udp_options = get_udp_options(inet_family, address, socket_options)
    case :gen_udp.open(port, udp_options) do
      {:ok, socket} ->
        Logger.info("UDP server #{:inet_parse.ntoa(address)} opened socket #{inspect socket}")
        {:ok, socket}
      {:error, :eacces} ->
        Logger.error("Failed to open UDP socket on address #{:inet_parse.ntoa(address)} and " <>
                     "port #{inspect port}. Need to run as sudo?")
        {:error, :eacces}
      {:error, other_error} ->
        raise ArgumentError, "Couldn't open the socket: #{inspect other_error}"
    end
  end

  defp get_udp_options(inet_family, address, socket_options) do
    [
      inet_family,
      {:reuseaddr, true}, :binary,
      {:active, @active},
      {:read_packets, @read_packets},
      {:ip, address},
      {:recbuf, ExDns.udp_receive_buffer_size} |
      socket_options
    ]
  end

  defp name_from_module(module, inet_family) when is_atom(module) and is_atom(inet_family) do
    Module.concat(module, inet_family)
  end

end