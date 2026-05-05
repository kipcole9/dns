defmodule ExDns.Listener.DoQ do
  @moduledoc """
  DNS-over-QUIC (RFC 9250) — transport-agnostic stream handler.

  ## What's here

  A pure handler that takes one DNS-message frame from a QUIC
  stream (the same 2-byte length prefix + message body framing
  used by DoT, per RFC 9250 §4.2) and returns the framed
  response. The listener that owns the QUIC socket calls
  `handle_frame/2` for each message it reads off a stream.

  ## What's not here

  The QUIC socket itself. OTP doesn't ship a built-in QUIC server,
  and the available BEAM options (`:quicer`, which NIF-wraps
  msquic) require a C library at the system level. Rather than
  pull in that platform-specific dep speculatively, this module
  carries the framing + resolution logic and leaves the QUIC
  binding as a thin wiring task for operators who need it.

  ## Wiring (when QUIC is available)

  The integration is roughly:

      # Pseudocode — operators glue this into their QUIC stream
      # handler (quicer, Bandit HTTP/3, whatever).
      def handle_stream_data(stream, data, state) do
        {:ok, response_bytes} =
          ExDns.Listener.DoQ.handle_frame(data, %{
            client_ip: state.peer_ip,
            transport: :doq
          })

        :quicer.send(stream, response_bytes)
        {:close, state}
      end

  Per RFC 9250 §4.3 each query gets its own bidirectional stream
  and the stream is closed after the response is sent.

  ## ALPN

  RFC 9250 §4.1 mandates ALPN token `"doq"`. The operator's QUIC
  listener must advertise this; this handler doesn't touch
  transport-level negotiation.
  """

  alias ExDns.Message

  @doc """
  Process one DNS-over-QUIC frame: framed length + message body
  in, framed response out.

  ### Arguments

  * `frame` is the raw stream bytes — 2-byte big-endian length
    followed by `length` bytes of DNS message.

  * `context` is a map carrying transport context:

      * `:client_ip` — the source-address tuple (used by the
        cookies + ECS post-processors).

  ### Returns

  * `{:ok, response_bytes}` — the framed response ready to write
    back to the QUIC stream.

  * `{:error, :truncated}` — the frame is shorter than its
    advertised length.

  * `{:error, :decode_failed}` — the bytes inside the frame
    couldn't be parsed as a DNS message.

  ### Examples

      iex> ExDns.Listener.DoQ.handle_frame(<<0, 0>>, %{client_ip: {127, 0, 0, 1}})
      {:error, :decode_failed}

  """
  @spec handle_frame(binary(), map()) ::
          {:ok, binary()} | {:error, :truncated | :decode_failed}
  def handle_frame(<<length::size(16), body::binary-size(length)>>, context) do
    case Message.decode(body) do
      {:ok, query} ->
        {:ok, framed_response(query, context)}

      {:error, _} ->
        {:error, :decode_failed}
    end
  end

  def handle_frame(<<length::size(16), _body::binary>> = short, _context)
      when byte_size(short) < length + 2 do
    {:error, :truncated}
  end

  def handle_frame(_, _), do: {:error, :truncated}

  # ----- internals --------------------------------------------------

  defp framed_response(query, context) do
    request =
      ExDns.Request.new(query,
        source_ip: Map.get(context, :client_ip),
        source_port: nil,
        transport: :doq
      )

    raw_response = ExDns.resolver_module().resolve(request)

    response =
      raw_response
      |> then(&ExDns.Cookies.PostProcess.process(query, &1, Map.get(context, :client_ip)))
      |> then(&ExDns.EDNSClientSubnet.PostProcess.process(query, &1))
      |> maybe_pad(query)

    bytes = Message.encode(response)
    <<byte_size(bytes)::size(16), bytes::binary>>
  end

  defp maybe_pad(response, query) do
    if ExDns.EDNSPadding.requested?(query) do
      ExDns.EDNSPadding.pad(response)
    else
      response
    end
  end
end
