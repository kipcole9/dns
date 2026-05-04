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
           {:ok, message_bytes} <- ThousandIsland.Socket.recv(socket, length, @idle_timeout) do
        {source_ip, source_port} = peer_info(socket)

        case ExDns.TSIG.Wire.verify_inbound(message_bytes) do
          {:ok, query, tsig_context} ->
            request =
              ExDns.Request.new(query,
                source_ip: source_ip,
                source_port: source_port,
                transport: :tcp
              )

            start_metadata = query_metadata(query, source_ip, source_port)
            start_time = System.monotonic_time()

            :telemetry.execute(
              [:ex_dns, :query, :start],
              %{system_time: System.system_time()},
              start_metadata
            )

            raw_response =
              case transfer_acl_decision(query, source_ip, tsig_context) do
                :allow ->
                  ExDns.resolver_module().resolve(request)

                :refuse ->
                  refused_response(query)
              end

            response =
              query
              |> ExDns.Cookies.PostProcess.process(raw_response, source_ip)
              |> maybe_pad(query)

            :telemetry.execute(
              [:ex_dns, :query, :stop],
              %{duration: System.monotonic_time() - start_time},
              Map.merge(start_metadata, response_metadata(response))
            )

            case ExDns.TSIG.Wire.sign_outbound(response, tsig_context) do
              {:ok, response_bytes} ->
                :ok =
                  ThousandIsland.Socket.send(
                    socket,
                    <<byte_size(response_bytes)::size(16), response_bytes::binary>>
                  )

                handle_one(socket, state)

              {:error, reason} ->
                Logger.error("TCP DNS handler: response signing failed: #{inspect(reason)}")
                {:close, state}
            end

          {:tsig_error, reason, _query} ->
            Logger.warning("TCP DNS handler: TSIG verification failed: #{inspect(reason)}")
            {:close, state}

          {:error, reason} ->
            Logger.error("TCP DNS handler: decode failed: #{inspect(reason)}")
            {:close, state}
        end
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

    defp peer_info(socket) do
      case ThousandIsland.Socket.peername(socket) do
        {:ok, {ip, port}} -> {ip, port}
        _ -> {nil, nil}
      end
    end

    defp query_metadata(%ExDns.Message{question: %{host: host, type: type}}, ip, port) do
      %{transport: :tcp, qname: host, qtype: type, client: {ip, port}}
    end

    defp query_metadata(_, ip, port) do
      %{transport: :tcp, qname: nil, qtype: nil, client: {ip, port}}
    end

    defp response_metadata(%ExDns.Message{header: %{rc: rcode, anc: anc}}) do
      %{rcode: rcode, answer_count: anc, validation: :none, cache: :none}
    end

    defp response_metadata(_) do
      %{rcode: nil, answer_count: 0, validation: :none, cache: :none}
    end

    # Only AXFR/IXFR queries are gated by the transfer ACL — every
    # other query type passes through unconditionally.
    defp transfer_acl_decision(%ExDns.Message{question: %{type: type, host: host}}, source_ip, tsig_context)
         when type in [:axfr, :ixfr] do
      key_name =
        case tsig_context do
          %{key_name: name} -> name
          _ -> nil
        end

      ExDns.Transfer.ACL.check(host, source_ip, key_name)
    end

    defp transfer_acl_decision(_, _, _), do: :allow

    # Apply EDNS padding when the query advertised it. RFC 8467
    # §6.2: "REQUIRED" on encrypted transports — `tcp_listener` is
    # used by both plain TCP and DoT, but the gating
    # `EDNSPadding.requested?/1` ensures we only pad clients that
    # asked.
    defp maybe_pad(response, query) do
      if ExDns.EDNSPadding.requested?(query) do
        ExDns.EDNSPadding.pad(response)
      else
        response
      end
    end

    # Build a REFUSED response that mirrors the query's header so
    # the TSIG signer can still chain its MAC.
    defp refused_response(%ExDns.Message{header: header} = query) do
      %ExDns.Message{
        query
        | header: %{header | qr: 1, aa: 0, ra: 0, ad: 0, cd: 0, rc: 5, anc: 0, auc: 0, adc: 0},
          answer: [],
          authority: [],
          additional: []
      }
    end
  end
end
