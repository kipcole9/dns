defmodule ExDns.Recursor.Client do
  @moduledoc """
  Outbound DNS client used by the recursive resolver.

  Sends a query message to a target IP over UDP, retries over TCP if
  the response has TC=1 set, and returns the decoded response or an
  error tuple.

  EDNS0 is advertised on every outbound query (1232-byte payload size
  matching DNS Flag Day 2020) so most upstreams will not truncate the
  reply.

  This module is intentionally stateless — concurrency control,
  retries against multiple servers, and timing budgets are the
  iterator's job.

  """

  alias ExDns.Message

  @udp_timeout 2_000
  @tcp_timeout 4_000

  @doc """
  Sends `query` to `address` and returns the decoded response.

  ### Arguments

  * `address` is an `:inet.ip_address()` (IPv4 or IPv6).
  * `query` is an `%ExDns.Message{}` to send.
  * `options` is a keyword list:
    * `:port` (default `53`)
    * `:transport` — `:auto` (UDP, retry over TCP on TC; the default),
      `:udp` (UDP only), `:tcp` (TCP only).
    * `:udp_timeout` and `:tcp_timeout` override the defaults.

  ### Returns

  * `{:ok, %ExDns.Message{}}` on a decoded response.
  * `{:error, reason}` otherwise (`:timeout`, `:closed`, `:nxdomain`, etc).

  """
  @spec query(:inet.ip_address(), Message.t(), keyword()) ::
          {:ok, Message.t()} | {:error, term()}
  def query(address, %Message{} = query, options \\ []) do
    transport = Keyword.get(options, :transport, :auto)
    port = Keyword.get(options, :port, 53)
    query_bytes = Message.encode(query)

    case transport do
      :tcp ->
        do_tcp(address, port, query_bytes, options)

      :udp ->
        do_udp(address, port, query_bytes, options)

      :auto ->
        case do_udp(address, port, query_bytes, options) do
          {:ok, %Message{header: %Message.Header{tc: 1}}} ->
            do_tcp(address, port, query_bytes, options)

          other ->
            other
        end
    end
  end

  defp do_udp(address, port, query_bytes, options) do
    timeout = Keyword.get(options, :udp_timeout, @udp_timeout)
    inet_family = inet_family(address)

    case :gen_udp.open(0, [inet_family, :binary, {:active, false}]) do
      {:ok, socket} ->
        try do
          with :ok <- :gen_udp.send(socket, address, port, query_bytes),
               {:ok, {_, _, response_bytes}} <- :gen_udp.recv(socket, 0, timeout),
               {:ok, response} <- Message.decode(response_bytes) do
            {:ok, response}
          end
        after
          :gen_udp.close(socket)
        end

      {:error, _} = error ->
        error
    end
  end

  defp do_tcp(address, port, query_bytes, options) do
    timeout = Keyword.get(options, :tcp_timeout, @tcp_timeout)
    inet_family = inet_family(address)

    case :gen_tcp.connect(address, port, [inet_family, :binary, {:active, false}], timeout) do
      {:ok, socket} ->
        try do
          framed = <<byte_size(query_bytes)::size(16), query_bytes::binary>>

          with :ok <- :gen_tcp.send(socket, framed),
               {:ok, <<length::size(16)>>} <- :gen_tcp.recv(socket, 2, timeout),
               {:ok, response_bytes} <- :gen_tcp.recv(socket, length, timeout),
               {:ok, response} <- Message.decode(response_bytes) do
            {:ok, response}
          end
        after
          :gen_tcp.close(socket)
        end

      {:error, _} = error ->
        error
    end
  end

  defp inet_family(address) when tuple_size(address) == 4, do: :inet
  defp inet_family(address) when tuple_size(address) == 8, do: :inet6
end
