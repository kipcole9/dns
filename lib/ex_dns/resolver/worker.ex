defmodule ExDns.Resolver.Worker do
  use GenServer
  require Logger
  alias ExDns.Resolver
  alias ExDns.Message
  alias ExDns.Instrumenter

  def start_link(%{resolver: resolver}) do
    :gen_server.start_link(__MODULE__, resolver, [])
  end

  def init(resolver) do
    {:ok, resolver}
  end

  def handle_call({:tcp_query, socket, bin}, _from, resolver) do
    {:reply, resolver.resolve(socket, bin), resolver}
  end

  def handle_call(_request, _from, resolver) do
    {:reply, :ok, resolver}
  end

  def handle_cast({:udp_query, address, port, socket, message}, resolver) do
    case Message.decode(message) do
      {:ok, message} ->
        try do
          resolver.resolve(message)
          |> Message.encode()
          |> send_udp_response(address, port, socket)
        catch
          error ->
            Logger.error("Resolver crashed: #{inspect(error)}")
        after
          :poolboy.checkin(Resolver.Supervisor.pool_name(), self())
        end

      {:error, reason} ->
        IO.puts("ERROR: #{inspect(reason)}")
    end

    {:noreply, resolver}
  end

  def handle_cast(_message, resolver) do
    {:noreply, resolver}
  end

  def handle_info(_info, resolver) do
    {:noreply, resolver}
  end

  def terminate(_reason, _resolver) do
    :ok
  end

  def code_change(_old_vsn, resolver, _extra) do
    {:ok, resolver}
  end

  defp send_udp_response(answer, address, port, socket) do
    IO.inspect("Would be sending: #{inspect(answer)} to socket #{inspect(socket)}")
  end
end
