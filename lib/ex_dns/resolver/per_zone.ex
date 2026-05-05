defmodule ExDns.Resolver.PerZone do
  @moduledoc """
  Resolver wrapper that routes each query to a per-zone
  upstream list (forwarder) when the qname matches a configured
  zone, and falls through to a configurable default resolver
  otherwise.

  ## Why

  Today's `ExDns.Resolver.Forwarder` is a global stub: every
  query goes to the same upstream list. Real BIND deployments
  routinely need:

  > forward `*.internal.example` to `10.0.0.5:53`,
  > forward `*.ad.example` to `10.0.0.6:53`,
  > recurse / authoritatively answer everything else.

  That's exactly what this resolver does. The routing decision
  is made by `ExDns.Resolver.PerZoneRouter` (longest-suffix
  match), and dispatch is done in-process via the existing
  `ExDns.Resolver.Forwarder` UDP path.

  ## Configuration

      config :ex_dns,
        resolver_module: ExDns.Resolver.PerZone,
        per_zone_forwarders: %{
          "internal.example" => [{{10, 0, 0, 5}, 53}],
          "ad.example"       => [{{10, 0, 0, 6}, 53}]
        },
        per_zone: [
          underlying: ExDns.Resolver.Default,    # default
          timeout:    5_000                       # default
        ]

  Set `:underlying` to `ExDns.Resolver.Hybrid` to recurse for
  unmatched queries instead of answering authoritatively, or to
  the global `ExDns.Resolver.Forwarder` to forward unmatched
  queries to a separate upstream list (a common BIND `forwarders
  { ... }` arrangement).

  ## Telemetry

  `[:ex_dns, :per_zone, :route]` fires per query with metadata
  `%{decision: :forward | :passthru, qname, qtype, zone}`
  (`:zone` is `nil` on `:passthru`).
  """

  alias ExDns.Message
  alias ExDns.Message.Header
  alias ExDns.Request
  alias ExDns.Resolver.PerZoneRouter

  require Logger

  @default_timeout 5_000

  @doc """
  Resolve a request via the per-zone routing table.

  Same shape as `ExDns.Resolver.Default.resolve/1` so the
  listener can swap to this resolver via `:resolver_module`.

  ### Arguments

  * `request_or_message` — `%ExDns.Request{}` or `%ExDns.Message{}`.

  ### Returns

  * `%ExDns.Message{}` — either the forwarded response, the
    underlying resolver's response, or a SERVFAIL when the
    forwarder couldn't reach any upstream.
  """
  @spec resolve(Request.t() | Message.t()) :: Message.t() | nil
  def resolve(%Request{message: message} = request) do
    do_resolve(message, request)
  end

  def resolve(%Message{} = message) do
    do_resolve(message, nil)
  end

  defp do_resolve(%Message{question: question} = message, request) do
    qname = question.host

    case PerZoneRouter.route(qname) do
      {:forward, zone, upstreams} ->
        :telemetry.execute(
          [:ex_dns, :per_zone, :route],
          %{count: 1},
          %{decision: :forward, qname: qname, qtype: question.type, zone: zone}
        )

        forward_to(upstreams, message)

      :passthru ->
        :telemetry.execute(
          [:ex_dns, :per_zone, :route],
          %{count: 1},
          %{decision: :passthru, qname: qname, qtype: question.type, zone: nil}
        )

        defer(message, request)
    end
  end

  # ----- forwarding ------------------------------------------------

  defp forward_to(upstreams, %Message{} = query) do
    bytes = Message.encode(query)
    timeout = config_timeout()

    case try_upstreams(upstreams, bytes, timeout, query.header.id) do
      {:ok, response_bytes} ->
        case Message.decode(response_bytes) do
          {:ok, response} -> response
          {:error, _} -> servfail(query)
        end

      {:error, _} ->
        servfail(query)
    end
  end

  defp try_upstreams([], _bytes, _timeout, _id), do: {:error, :no_upstreams}

  defp try_upstreams([{ip, port} | rest], bytes, timeout, expected_id) do
    case query_upstream(ip, port, bytes, timeout, expected_id) do
      {:ok, _} = ok ->
        ok

      {:error, reason} ->
        Logger.warning(
          "ExDns.Resolver.PerZone: upstream #{:inet.ntoa(ip)}:#{port} failed: #{inspect(reason)}"
        )

        try_upstreams(rest, bytes, timeout, expected_id)
    end
  end

  defp query_upstream(ip, port, bytes, timeout, expected_id) do
    case :gen_udp.open(0, [:binary, active: false]) do
      {:ok, socket} ->
        try do
          with :ok <- :gen_udp.send(socket, ip, port, bytes),
               {:ok, response_bytes} <- recv_matching(socket, timeout, expected_id) do
            {:ok, response_bytes}
          end
        after
          :gen_udp.close(socket)
        end

      {:error, _} = err ->
        err
    end
  end

  defp recv_matching(socket, timeout, expected_id) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_recv(socket, deadline, expected_id)
  end

  defp do_recv(socket, deadline, expected_id) do
    remaining = max(0, deadline - System.monotonic_time(:millisecond))

    case :gen_udp.recv(socket, 0, remaining) do
      {:ok, {_addr, _port, <<id::size(16), _::binary>> = bytes}} when id == expected_id ->
        {:ok, bytes}

      {:ok, _stale} ->
        do_recv(socket, deadline, expected_id)

      {:error, _} = err ->
        err
    end
  end

  defp servfail(%Message{header: %Header{} = header} = query) do
    %Message{
      query
      | header: %Header{
          header
          | qr: 1,
            aa: 0,
            ra: 1,
            ad: 0,
            cd: 0,
            rc: 2,
            anc: 0,
            auc: 0,
            adc: 0
        },
        answer: [],
        authority: [],
        additional: []
    }
  end

  # ----- passthru --------------------------------------------------

  defp defer(message, nil), do: underlying().resolve(message)
  defp defer(_message, request), do: underlying().resolve(request)

  defp underlying do
    Application.get_env(:ex_dns, :per_zone, [])
    |> Keyword.get(:underlying, ExDns.Resolver.Default)
  end

  defp config_timeout do
    Application.get_env(:ex_dns, :per_zone, [])
    |> Keyword.get(:timeout, @default_timeout)
  end
end
