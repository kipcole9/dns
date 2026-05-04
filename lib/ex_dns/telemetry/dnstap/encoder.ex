defmodule ExDns.Telemetry.Dnstap.Encoder do
  @moduledoc """
  Hand-rolled Protocol Buffers encoder for the `dnstap.proto`
  subset used by ExDns.

  We encode just enough of [dnstap.proto](https://github.com/dnstap/dnstap.pb)
  to produce frames acceptable to `dnstap-read`:

  ```proto
  message Dnstap {
    optional bytes   identity = 1;
    optional bytes   version  = 2;
    optional bytes   extra    = 3;
    enum Type { MESSAGE = 1; }
    required Type    type     = 15;
    optional Message message  = 14;
  }

  message Message {
    enum Type {
      AUTH_QUERY = 1; AUTH_RESPONSE = 2;
      RESOLVER_QUERY = 3; RESOLVER_RESPONSE = 4;
      CLIENT_QUERY = 5; CLIENT_RESPONSE = 6;
      ...
    }
    required Type     type            = 1;
    optional SocketFamily socket_family = 2;
    optional SocketProtocol socket_protocol = 3;
    optional bytes    query_address   = 4;
    optional bytes    response_address = 5;
    optional uint32   query_port      = 6;
    optional uint32   response_port   = 7;
    optional uint64   query_time_sec  = 8;
    optional fixed32  query_time_nsec = 9;
    optional bytes    query_message   = 10;
    optional bytes    query_zone      = 11;
    optional uint64   response_time_sec  = 12;
    optional fixed32  response_time_nsec = 13;
    optional bytes    response_message   = 14;
  }
  ```

  We hand-encode rather than pulling in `:protox` to keep the
  dependency graph minimal and to align with the project's
  bitstring-first wire-format philosophy.
  """

  import Bitwise

  # ---------- public API ----------

  @doc """
  Encode a dnstap frame for the given message type and metadata
  carried by an `ExDns.Telemetry` event.

  ### Arguments

  * `message_type` is one of `:auth_query`, `:auth_response`,
    `:client_query`, `:client_response`, `:resolver_query`,
    `:resolver_response`.

  * `metadata` is the metadata map from a `[:ex_dns, :query, ...]`
    event. Recognised keys: `:client` (a `{ip, port}` tuple),
    `:transport`, `:qname`, `:qtype`, `:rcode`, `:answer_count`.

  ### Returns

  * Binary protobuf-encoded `Dnstap` envelope wrapping the inner
    `Message`. Suitable as a Frame Streams payload.

  ### Examples

      iex> bytes = ExDns.Telemetry.Dnstap.Encoder.encode(:auth_query, %{
      ...>   transport: :udp,
      ...>   qname: "example.test",
      ...>   qtype: :a,
      ...>   client: {{127, 0, 0, 1}, 53_000}
      ...> })
      iex> is_binary(bytes) and byte_size(bytes) > 0
      true

  """
  @spec encode(atom(), map()) :: binary()
  def encode(message_type, metadata) when is_atom(message_type) and is_map(metadata) do
    inner = encode_message(message_type, metadata)
    encode_envelope(inner)
  end

  # ---------- envelope ----------

  # message Dnstap {
  #   optional bytes identity  = 1; (tag 1, wire 2)
  #   optional bytes version   = 2; (tag 2, wire 2)
  #   required Type  type      = 15; (tag 15, wire 0) — value 1 = MESSAGE
  #   optional Message message = 14; (tag 14, wire 2)
  # }
  defp encode_envelope(inner_message_bytes) do
    identity = identity_string()
    version = version_string()

    IO.iodata_to_binary([
      field(1, :bytes, identity),
      field(2, :bytes, version),
      field(15, :varint, 1),
      field(14, :bytes, inner_message_bytes)
    ])
  end

  defp identity_string do
    case :inet.gethostname() do
      {:ok, host} -> List.to_string(host)
      _ -> "ex_dns"
    end
  end

  defp version_string do
    case :application.get_key(:ex_dns, :vsn) do
      {:ok, vsn} -> "ExDns " <> List.to_string(vsn)
      _ -> "ExDns"
    end
  end

  # ---------- inner Message ----------

  defp encode_message(message_type, metadata) do
    type_value = message_type_value(message_type)
    {family, address_bytes} = socket_family(metadata[:client])
    protocol = socket_protocol(metadata[:transport])
    {ip_port, query_port} = peer_port(metadata[:client])
    _ = ip_port

    {time_sec, time_nsec} = wallclock_now()

    parts = [
      field(1, :varint, type_value),
      field(2, :varint, family),
      field(3, :varint, protocol),
      field(4, :bytes, address_bytes),
      field(6, :varint, query_port)
    ]

    parts =
      case message_type do
        kind when kind in [:auth_query, :resolver_query, :client_query] ->
          parts ++
            [
              field(8, :varint, time_sec),
              field(9, :fixed32, time_nsec)
            ]

        _ ->
          parts ++
            [
              field(12, :varint, time_sec),
              field(13, :fixed32, time_nsec)
            ]
      end

    qname_bytes = qname_to_wire(metadata[:qname])
    parts = parts ++ [field(11, :bytes, qname_bytes)]

    IO.iodata_to_binary(parts)
  end

  defp message_type_value(:auth_query), do: 1
  defp message_type_value(:auth_response), do: 2
  defp message_type_value(:resolver_query), do: 3
  defp message_type_value(:resolver_response), do: 4
  defp message_type_value(:client_query), do: 5
  defp message_type_value(:client_response), do: 6
  defp message_type_value(_), do: 0

  defp socket_family({ip, _port}) when tuple_size(ip) == 4 do
    {1, ipv4_to_bytes(ip)}
  end

  defp socket_family({ip, _port}) when tuple_size(ip) == 8 do
    {2, ipv6_to_bytes(ip)}
  end

  defp socket_family(_), do: {1, <<0, 0, 0, 0>>}

  defp socket_protocol(:udp), do: 1
  defp socket_protocol(:tcp), do: 2
  defp socket_protocol(:doh), do: 6
  defp socket_protocol(_), do: 1

  defp peer_port({_ip, port}) when is_integer(port), do: {nil, port}
  defp peer_port(_), do: {nil, 0}

  defp ipv4_to_bytes({a, b, c, d}), do: <<a, b, c, d>>

  defp ipv6_to_bytes({a, b, c, d, e, f, g, h}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end

  defp qname_to_wire(nil), do: <<0>>

  defp qname_to_wire(name) when is_binary(name) do
    name
    |> String.trim_trailing(".")
    |> String.split(".")
    |> Enum.reduce(<<>>, fn label, acc ->
      bytes = label
      acc <> <<byte_size(bytes)::8, bytes::binary>>
    end)
    |> Kernel.<>(<<0>>)
  end

  defp wallclock_now do
    micro = :os.system_time(:microsecond)
    sec = div(micro, 1_000_000)
    nsec = rem(micro, 1_000_000) * 1_000
    {sec, nsec}
  end

  # ---------- protobuf primitives ----------

  # field(field_number, wire_type, value) → iodata for the encoded field.
  # wire types: :varint=0, :fixed64=1, :bytes=2, :fixed32=5
  @doc false
  def field(_, _, nil), do: <<>>

  def field(num, :varint, value) when is_integer(value) and value >= 0 do
    [varint(num <<< 3 ||| 0), varint(value)]
  end

  def field(num, :fixed32, value) when is_integer(value) and value >= 0 do
    [varint(num <<< 3 ||| 5), <<value::little-32>>]
  end

  def field(num, :bytes, bin) when is_binary(bin) do
    [varint(num <<< 3 ||| 2), varint(byte_size(bin)), bin]
  end

  @doc false
  def varint(value) when is_integer(value) and value >= 0 do
    do_varint(value, [])
  end

  defp do_varint(value, acc) when value < 0x80 do
    IO.iodata_to_binary(Enum.reverse([<<value>> | acc]))
  end

  defp do_varint(value, acc) do
    byte = (value &&& 0x7F) ||| 0x80
    do_varint(value >>> 7, [<<byte>> | acc])
  end
end
