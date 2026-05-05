defmodule ExDns.Resource.SVCB.Params do
  @moduledoc """
  Typed encode/decode for SVCB SvcParams per RFC 9460 §7.

  The base `ExDns.Resource.SVCB` and `ExDns.Resource.HTTPS`
  structs surface `:params` as raw `{key_int, value_binary}`
  tuples. This module turns that raw form into a tagged keyword
  list matching the named keys defined by RFC 9460 + the IANA
  Service Parameter Keys registry, and back again.

  ## Recognised keys

  | Key | Atom              | Value shape                                   |
  |-----|-------------------|-----------------------------------------------|
  |  0  | `:mandatory`      | `[atom()]` — list of mandatory key names      |
  |  1  | `:alpn`           | `[binary()]` — ALPN tokens (e.g. `["h2"]`)    |
  |  2  | `:no_default_alpn`| `true` (empty value, presence is the signal)  |
  |  3  | `:port`           | `0..65535`                                    |
  |  4  | `:ipv4hint`       | `[{0..255, …}]` — list of IPv4 tuples         |
  |  5  | `:ech`            | `binary()` — opaque ECHConfig                 |
  |  6  | `:ipv6hint`       | `[{0..65535, …}]` — list of IPv6 tuples       |

  Unknown keys remain as `{key_int, raw_binary}` tuples so
  forwards-compatibility with future SvcParamKeys works without a
  library update.

  ## API

      iex> raw = [
      ...>   {1, <<2, "h2">>},
      ...>   {3, <<443::16>>},
      ...>   {4, <<192, 0, 2, 1>>}
      ...> ]
      iex> ExDns.Resource.SVCB.Params.decode(raw)
      [alpn: ["h2"], port: 443, ipv4hint: [{192, 0, 2, 1}]]

      iex> ExDns.Resource.SVCB.Params.encode(alpn: ["h2"], port: 443)
      [{1, <<2, "h2">>}, {3, <<443::16>>}]
  """

  @doc """
  Decode a list of raw `{key_int, binary}` tuples into typed
  `{atom_or_int, value}` entries.

  Unknown keys pass through unchanged so callers can still
  inspect them.

  ### Examples

      iex> ExDns.Resource.SVCB.Params.decode([])
      []

  """
  @spec decode([{non_neg_integer(), binary()}]) :: keyword()
  def decode(raw) when is_list(raw) do
    Enum.map(raw, &decode_one/1)
  end

  @doc """
  Encode a typed parameter list back to the raw
  `{key_int, binary}` form that the SVCB/HTTPS encoder consumes.

  Unknown integer-keyed entries pass through.

  ### Examples

      iex> ExDns.Resource.SVCB.Params.encode([])
      []

  """
  @spec encode(keyword()) :: [{non_neg_integer(), binary()}]
  def encode(typed) when is_list(typed) do
    Enum.map(typed, &encode_one/1)
  end

  # ----- decode -----------------------------------------------------

  defp decode_one({0, value}), do: {:mandatory, decode_mandatory(value, [])}
  defp decode_one({1, value}), do: {:alpn, decode_alpn(value, [])}
  defp decode_one({2, _value}), do: {:no_default_alpn, true}
  defp decode_one({3, <<port::size(16)>>}), do: {:port, port}
  defp decode_one({4, value}), do: {:ipv4hint, decode_ipv4_list(value, [])}
  defp decode_one({5, value}), do: {:ech, value}
  defp decode_one({6, value}), do: {:ipv6hint, decode_ipv6_list(value, [])}
  defp decode_one(other), do: other

  defp decode_mandatory(<<>>, acc), do: Enum.reverse(acc)

  defp decode_mandatory(<<key::size(16), rest::binary>>, acc) do
    decode_mandatory(rest, [key_atom(key) | acc])
  end

  defp decode_alpn(<<>>, acc), do: Enum.reverse(acc)

  defp decode_alpn(<<len::size(8), token::binary-size(len), rest::binary>>, acc) do
    decode_alpn(rest, [token | acc])
  end

  defp decode_alpn(_, acc), do: Enum.reverse(acc)

  defp decode_ipv4_list(<<>>, acc), do: Enum.reverse(acc)

  defp decode_ipv4_list(<<a, b, c, d, rest::binary>>, acc) do
    decode_ipv4_list(rest, [{a, b, c, d} | acc])
  end

  defp decode_ipv4_list(_, acc), do: Enum.reverse(acc)

  defp decode_ipv6_list(<<>>, acc), do: Enum.reverse(acc)

  defp decode_ipv6_list(<<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16, rest::binary>>, acc) do
    decode_ipv6_list(rest, [{a, b, c, d, e, f, g, h} | acc])
  end

  defp decode_ipv6_list(_, acc), do: Enum.reverse(acc)

  # ----- encode -----------------------------------------------------

  defp encode_one({:mandatory, keys}) when is_list(keys) do
    bytes =
      keys
      |> Enum.map(fn k -> <<key_int(k)::size(16)>> end)
      |> IO.iodata_to_binary()

    {0, bytes}
  end

  defp encode_one({:alpn, tokens}) when is_list(tokens) do
    bytes =
      tokens
      |> Enum.map(fn t -> <<byte_size(t)::size(8), t::binary>> end)
      |> IO.iodata_to_binary()

    {1, bytes}
  end

  defp encode_one({:no_default_alpn, true}), do: {2, <<>>}

  defp encode_one({:port, port}) when is_integer(port) and port in 0..0xFFFF do
    {3, <<port::size(16)>>}
  end

  defp encode_one({:ipv4hint, addrs}) when is_list(addrs) do
    bytes =
      addrs
      |> Enum.map(fn {a, b, c, d} -> <<a, b, c, d>> end)
      |> IO.iodata_to_binary()

    {4, bytes}
  end

  defp encode_one({:ech, blob}) when is_binary(blob), do: {5, blob}

  defp encode_one({:ipv6hint, addrs}) when is_list(addrs) do
    bytes =
      addrs
      |> Enum.map(fn {a, b, c, d, e, f, g, h} ->
        <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
      end)
      |> IO.iodata_to_binary()

    {6, bytes}
  end

  # Unrecognised typed key — pass through if it's already in raw
  # {int, binary} form.
  defp encode_one({key_int, value}) when is_integer(key_int) and is_binary(value) do
    {key_int, value}
  end

  # ----- key registry ----------------------------------------------

  defp key_atom(0), do: :mandatory
  defp key_atom(1), do: :alpn
  defp key_atom(2), do: :no_default_alpn
  defp key_atom(3), do: :port
  defp key_atom(4), do: :ipv4hint
  defp key_atom(5), do: :ech
  defp key_atom(6), do: :ipv6hint
  defp key_atom(other), do: other

  defp key_int(:mandatory), do: 0
  defp key_int(:alpn), do: 1
  defp key_int(:no_default_alpn), do: 2
  defp key_int(:port), do: 3
  defp key_int(:ipv4hint), do: 4
  defp key_int(:ech), do: 5
  defp key_int(:ipv6hint), do: 6
  defp key_int(int) when is_integer(int), do: int
end
