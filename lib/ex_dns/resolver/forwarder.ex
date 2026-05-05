defmodule ExDns.Resolver.Forwarder do
  @moduledoc """
  Stub-resolver / forwarder mode: instead of recursing through
  the DNS hierarchy itself, ExDns forwards each query to one or
  more configured upstream resolvers (e.g. `1.1.1.1`, `8.8.8.8`,
  or a corporate resolver) and relays the response.

  ## When to use this

  * The local server should not bear the recursion load — let a
    public resolver do it.
  * Corporate / split-horizon: forward `*.internal` to an
    internal resolver, everything else to a public one (split
    routing is a follow-up; this MVP forwards everything to one
    upstream list in order).
  * Lightweight cache-in-front-of-cache deployments.

  ## Configuration

      config :ex_dns,
        resolver_module: ExDns.Resolver.Forwarder,
        forwarder: [
          upstreams: [{{1, 1, 1, 1}, 53}, {{8, 8, 8, 8}, 53}],
          timeout: 5_000
        ]

  ## Wire path

  Each query goes out as a fresh UDP datagram. The forwarder
  matches the response by transaction ID. On timeout it tries
  the next upstream; if all fail, it returns SERVFAIL (rcode 2)
  to the client.

  ## What's not here

  * EDNS0 echo / TCP fallback on TC=1 — both straightforward
    follow-ups.
  * Per-zone routing (split horizon) — needs a small route table
    in front of `resolve/1`.
  * Response caching — the recursor cache is already wired and
    can be opt-in attached.
  """

  alias ExDns.Message
  alias ExDns.Message.Header
  alias ExDns.Request

  require Logger

  @default_timeout 5_000

  @doc """
  Resolve a query by forwarding to the configured upstreams.

  Implements the same shape as `ExDns.Resolver.Default.resolve/1`
  so the listener can swap forwarder mode in via the
  `:resolver_module` config key.

  ### Arguments

  * `request_or_message` — either an `%ExDns.Request{}` or a
    raw `%ExDns.Message{}`.

  ### Returns

  * `%ExDns.Message{}` — the relayed response, or a SERVFAIL
    response when no upstream answered.

  ### Examples

      iex> Application.delete_env(:ex_dns, :forwarder)
      iex> message = %ExDns.Message{
      ...>   header: %ExDns.Message.Header{id: 0, qr: 0, oc: 0, aa: 0, tc: 0,
      ...>                                  rd: 1, ra: 0, ad: 0, cd: 0, rc: 0,
      ...>                                  qc: 1, anc: 0, auc: 0, adc: 0},
      ...>   question: %ExDns.Message.Question{host: "x.test", type: :a, class: :in},
      ...>   answer: [], authority: [], additional: []
      ...> }
      iex> response = ExDns.Resolver.Forwarder.resolve(message)
      iex> response.header.rc
      2

  """
  @spec resolve(Message.t() | Request.t()) :: Message.t()
  def resolve(%Request{message: message}), do: resolve(message)

  def resolve(%Message{} = query) do
    config = read_config()
    bytes = Message.encode(query)

    case try_upstreams(config.upstreams, bytes, config.timeout, query.header.id) do
      {:ok, response_bytes} ->
        case Message.decode(response_bytes) do
          {:ok, response} -> response
          {:error, _} -> servfail(query)
        end

      {:error, _} ->
        servfail(query)
    end
  end

  # ----- internals --------------------------------------------------

  defp read_config do
    options = Application.get_env(:ex_dns, :forwarder, [])

    %{
      upstreams: Keyword.get(options, :upstreams, []),
      timeout: Keyword.get(options, :timeout, @default_timeout)
    }
  end

  defp try_upstreams([], _bytes, _timeout, _id) do
    {:error, :no_upstreams}
  end

  defp try_upstreams([{ip, port} | rest], bytes, timeout, id) do
    case query_upstream(ip, port, bytes, timeout, id) do
      {:ok, _} = ok ->
        :telemetry.execute(
          [:ex_dns, :forwarder, :upstream, :ok],
          %{count: 1},
          %{upstream: {ip, port}}
        )

        ok

      {:error, reason} ->
        Logger.warning(
          "ExDns.Resolver.Forwarder: upstream #{:inet.ntoa(ip)}:#{port} failed: #{inspect(reason)}"
        )

        :telemetry.execute(
          [:ex_dns, :forwarder, :upstream, :error],
          %{count: 1},
          %{upstream: {ip, port}, reason: reason}
        )

        try_upstreams(rest, bytes, timeout, id)
    end
  end

  defp query_upstream(ip, port, bytes, timeout, expected_id) do
    case :gen_udp.open(0, [:binary, active: false]) do
      {:ok, socket} ->
        try do
          with :ok <- :gen_udp.send(socket, ip, port, bytes),
               {:ok, response_bytes} <- recv_matching_id(socket, timeout, expected_id) do
            {:ok, response_bytes}
          end
        after
          :gen_udp.close(socket)
        end

      {:error, _} = err ->
        err
    end
  end

  # Read until we either get a response with the expected
  # transaction id or the timeout elapses. Mismatched ids could
  # mean a delayed packet from a previous query — drop it and
  # keep waiting.
  defp recv_matching_id(socket, timeout, expected_id) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_recv_matching(socket, deadline, expected_id)
  end

  defp do_recv_matching(socket, deadline, expected_id) do
    remaining = max(0, deadline - System.monotonic_time(:millisecond))

    case :gen_udp.recv(socket, 0, remaining) do
      {:ok, {_addr, _port, <<id::size(16), _::binary>> = bytes}} when id == expected_id ->
        {:ok, bytes}

      {:ok, _stale} ->
        do_recv_matching(socket, deadline, expected_id)

      {:error, _} = err ->
        err
    end
  end

  # Build a SERVFAIL (rcode 2) response that mirrors the query
  # so the client gets back the same id + question.
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
end
