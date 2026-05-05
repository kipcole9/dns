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
        if notify?(query) and notify_acl_decision(query, message, address) == :refuse do
          # RFC 1996 §3.7: silently drop unauthenticated /
          # unauthorised NOTIFYs.
          :poolboy.checkin(Resolver.Supervisor.pool_name(), self())
        else
          handle_cast_after_acl(query, address, port, socket, resolver)
        end

      {:error, reason} ->
        Logger.error("Failed to decode incoming UDP DNS message: #{inspect(reason)}")
    end

    {:noreply, resolver}
  end

  def handle_cast(_message, resolver) do
    {:noreply, resolver}
  end

  defp handle_cast_after_acl(query, address, port, socket, resolver) do
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

      raw_response = resolver.resolve(request)

      response =
        raw_response
        |> then(&ExDns.Cookies.PostProcess.process(query, &1, address))
        |> then(&ExDns.EDNSClientSubnet.PostProcess.process(query, &1))

      budget = udp_budget(query)

      # RRL: ask whether this response is allowed out, may be
      # truncated to force TCP retry, or should be silently
      # dropped. Cookie-validated queries bypass the limiter.
      rrl_options = [
        address: address,
        cookie_validated: cookie_validated?(query, address)
      ]

      rrl_decision = rrl_check(query, response, rrl_options)

      case rrl_decision do
        :allow ->
          response_bytes = Message.encode_for_udp(response, budget)
          send_udp_response(response_bytes, address, port, socket)

        :slip ->
          truncated = truncate_response(response)
          response_bytes = Message.encode_for_udp(truncated, budget)
          send_udp_response(response_bytes, address, port, socket)

        :drop ->
          :ok
      end

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
          Map.merge(start_metadata, %{kind: kind, reason: reason, stacktrace: stack})
        )

        Logger.error("Resolver crashed: #{inspect({kind, reason})}")
    after
      :poolboy.checkin(Resolver.Supervisor.pool_name(), self())
    end
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

  # ----- NOTIFY ACL helpers ----------------------------------------

  defp notify?(%Message{header: %{oc: 4}}), do: true
  defp notify?(_), do: false

  # Verify TSIG on the raw bytes (so the MAC over the wire is
  # checkable), pull the key name out, then ask
  # `ExDns.Notify.ACL` whether the source IP + key combination
  # is permitted for the apex named in the question section.
  defp notify_acl_decision(%Message{question: %{host: apex}}, raw_bytes, source_ip) do
    key_name =
      case ExDns.TSIG.Wire.verify_inbound(raw_bytes) do
        {:ok, _, %{key_name: name}} -> name
        _ -> nil
      end

    ExDns.Notify.ACL.check(apex, source_ip, key_name)
  end

  defp notify_acl_decision(_query, _raw_bytes, _source_ip), do: :allow

  # ----- RRL helpers ------------------------------------------------

  # Did the query carry a verified DNS Cookie? Used to exempt
  # cookie-validated queries from RRL — they are demonstrably not
  # spoofed.
  defp cookie_validated?(%Message{additional: additional}, address) when is_list(additional) do
    with %ExDns.Resource.OPT{options: opts} <- Enum.find(additional, &match?(%ExDns.Resource.OPT{}, &1)),
         {:ok, client_cookie, server_cookie} when is_binary(server_cookie) <-
           ExDns.Cookies.find_in_options(opts),
         :ok <- ExDns.Cookies.verify(client_cookie, server_cookie, address) do
      true
    else
      _ -> false
    end
  end

  defp cookie_validated?(_, _), do: false

  # Categorise the response so RRL can budget different traffic
  # patterns separately (NXDOMAIN flood vs. legit answers).
  defp response_kind(%Message{header: %{rc: rcode, aa: aa}, answer: answer}) do
    cond do
      rcode == 3 -> :nxdomain
      rcode != 0 -> :error
      aa == 0 -> :referral
      answer == [] -> :nodata
      true -> :answer
    end
  end

  defp response_kind(_), do: :error

  defp rrl_check(%Message{question: %{host: host, type: type}} = _query, response, options) do
    ExDns.RRL.check(
      Keyword.get(options, :address, {0, 0, 0, 0}),
      host || "",
      type,
      response_kind(response),
      options
    )
  end

  defp rrl_check(_query, _response, _options), do: :allow

  # Build a TC=1 (truncated) response with empty sections — RFC 1035
  # §4.1.1: the client should retry over TCP. RRL's "slip" mechanism
  # uses this so legit clients caught in a punished bucket can
  # recover.
  defp truncate_response(%Message{header: header} = response) do
    %Message{
      response
      | header: %{header | tc: 1, anc: 0, auc: 0, adc: 0},
        answer: [],
        authority: [],
        additional: []
    }
  end

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
