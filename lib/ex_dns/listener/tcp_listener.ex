defmodule ExDns.Listener.TCP do
  @moduledoc """
  TCP listener for DNS messages (RFC 1035 §4.2.2 / RFC 7766).

  Built on `ThousandIsland`. Each connection is handled by a
  short-lived `ThousandIsland.Handler` that reads framed DNS messages,
  dispatches them through the configured resolver, and writes framed
  responses. Connections stay open for as long as the client wants
  (RFC 7766 §6.2.1.1) or until the per-message timeout expires.

  ## Wire framing

  Every DNS message on TCP is preceded by a two-byte length prefix
  giving the size of the message that follows. We use ThousandIsland's
  `read/3` to wait for the prefix and then for the full body.

  ## Child spec

  Returns a child spec suitable for adding under the application
  supervisor:

      {ExDns.Listener.TCP, port: 8053, address: {127, 0, 0, 1}}

  """

  require Logger

  alias ExDns.Message

  @doc false
  def child_spec(options) do
    options =
      options
      |> Keyword.put_new(:port, ExDns.listener_port())
      |> Keyword.put(:handler_module, __MODULE__.Handler)

    %{
      id: id_for(options),
      start: {ThousandIsland, :start_link, [options]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end

  defp id_for(options) do
    address = Keyword.get(options, :transport_options, [])[:ip] || :default
    port = Keyword.fetch!(options, :port)
    {__MODULE__, address, port}
  end

  defmodule Handler do
    @moduledoc false

    use ThousandIsland.Handler

    require Logger
    alias ExDns.Message

    # 5 seconds is the upper bound for waiting on the next request
    # frame from a single connection. RFC 7766 recommends an idle
    # timeout in this range for resource-constrained servers.
    @idle_timeout :timer.seconds(5)

    @impl ThousandIsland.Handler
    def handle_connection(socket, state) do
      handle_one(socket, state)
    end

    defp handle_one(socket, state) do
      with {:ok, <<length::size(16)>>} <- ThousandIsland.Socket.recv(socket, 2, @idle_timeout),
           {:ok, message_bytes} <- ThousandIsland.Socket.recv(socket, length, @idle_timeout),
           {:ok, query} <- Message.decode(message_bytes) do
        response = ExDns.resolver_module().resolve(query)
        response_bytes = Message.encode(response)
        :ok = ThousandIsland.Socket.send(socket, <<byte_size(response_bytes)::size(16), response_bytes::binary>>)
        handle_one(socket, state)
      else
        {:error, :closed} ->
          {:close, state}

        {:error, :timeout} ->
          {:close, state}

        {:error, reason} ->
          Logger.error("TCP DNS handler error: #{inspect(reason)}")
          {:close, state}
      end
    end
  end
end
