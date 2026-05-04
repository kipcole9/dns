defmodule ExDns.Resolver.Worker do
  @moduledoc false

  use GenServer
  require Logger
  alias ExDns.Resolver
  alias ExDns.Message

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

  # RFC 1035 §2.3.4 default UDP payload size when the client does not
  # advertise a larger one via EDNS0.
  @default_udp_payload 512

  def handle_cast({:udp_query, address, port, socket, message}, resolver) do
    case Message.decode(message) do
      {:ok, query} ->
        start_metadata = query_metadata(query, address, port)
        start_time = System.monotonic_time()

        :telemetry.execute(
          [:ex_dns, :query, :start],
          %{system_time: System.system_time()},
          start_metadata
        )

        try do
          request =
            ExDns.Request.new(query,
              source_ip: address,
              source_port: port,
              transport: :udp
            )

          response = resolver.resolve(request)
          budget = udp_budget(query)
          response_bytes = Message.encode_for_udp(response, budget)
          send_udp_response(response_bytes, address, port, socket)

          :telemetry.execute(
            [:ex_dns, :query, :stop],
            %{duration: System.monotonic_time() - start_time},
            Map.merge(start_metadata, response_metadata(response))
          )
        catch
          kind, reason ->
            stack = __STACKTRACE__

            :telemetry.execute(
              [:ex_dns, :query, :exception],
              %{duration: System.monotonic_time() - start_time},
              Map.merge(start_metadata, %{
                kind: kind,
                reason: reason,
                stacktrace: stack
              })
            )

            Logger.error("Resolver crashed: #{inspect({kind, reason})}")
        after
          :poolboy.checkin(Resolver.Supervisor.pool_name(), self())
        end

      {:error, reason} ->
        Logger.error("Failed to decode incoming UDP DNS message: #{inspect(reason)}")
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

  # Build the metadata map shared by `:start` and `:stop` events.
  defp query_metadata(%Message{question: %{host: host, type: type}}, address, port) do
    %{
      transport: :udp,
      qname: host,
      qtype: type,
      client: {address, port}
    }
  end

  defp query_metadata(_query, address, port) do
    %{
      transport: :udp,
      qname: nil,
      qtype: nil,
      client: {address, port}
    }
  end

  # Pull rcode + answer count off the response. Validation status is
  # added by the resolver layer when it knows it; we default to :none.
  defp response_metadata(%Message{header: %{rc: rcode, anc: anc}, answer: answer}) do
    %{
      rcode: rcode,
      answer_count: anc,
      validation: validation_status(answer),
      cache: :none
    }
  end

  defp response_metadata(_response) do
    %{rcode: nil, answer_count: 0, validation: :none, cache: :none}
  end

  # Placeholder until per-request validation status is threaded through
  # the response. The hybrid resolver already sets AD on validated
  # answers; richer status will land with full resolver instrumentation.
  defp validation_status(_answer), do: :none

  # The UDP budget is the OPT record's advertised payload size, clamped
  # to a sensible upper bound. When no OPT was supplied, fall back to
  # the legacy 512-byte limit.
  defp udp_budget(%Message{additional: additional}) when is_list(additional) do
    Enum.find_value(additional, @default_udp_payload, fn
      %ExDns.Resource.OPT{payload_size: size} -> size
      _ -> nil
    end)
  end

  defp udp_budget(_), do: @default_udp_payload

  defp send_udp_response(reply_bytes, address, port, socket) when is_binary(reply_bytes) do
    case :gen_udp.send(socket, address, port, reply_bytes) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.error(
          "UDP send to #{:inet.ntoa(address)}:#{port} failed: #{inspect(reason)}"
        )

        :error
    end
  end
end
