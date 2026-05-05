defmodule ExDns.EDNSClientSubnet do
  @moduledoc """
  EDNS Client Subnet (ECS, RFC 7871).

  When a recursive resolver wants the authoritative server to
  tailor its answer to the *end client's* network (rather than the
  resolver's, which is what the server otherwise sees), it
  attaches an EDNS option code `8` carrying the client's
  source-address prefix.

  This module decodes the option from inbound queries and echoes
  it back in responses with `SCOPE=0`, signalling "the answer is
  valid for the entire SOURCE prefix" — i.e. ExDns isn't
  geo-tailoring its responses. That keeps caching downstream
  correct without us having to do any geo logic ourselves.

  ## Wire format (RFC 7871 §6)

      +-------+--------+--------+--------------+
      | OPTION-CODE = 8        | OPTION-LENGTH |
      +------------------------+---------------+
      | FAMILY (16) | SRC PREFIX-LEN | SCOPE | |
      +------------------------+---------------+
      | ADDRESS (variable, prefix-len bits)    |
      +----------------------------------------+

  * FAMILY: 1 = IPv4, 2 = IPv6
  * SRC PREFIX-LEN: bits significant in the client subnet.
  * SCOPE PREFIX-LEN: 0 in queries; in responses, the length the
    server's answer applies to.
  * ADDRESS: the leading SRC PREFIX-LEN bits of the client
    address, padded with zero bits to the next byte boundary.
  """

  @option_code 8

  @doc """
  Returns the option code (`8`).

  ### Examples

      iex> ExDns.EDNSClientSubnet.option_code()
      8

  """
  @spec option_code() :: 8
  def option_code, do: @option_code

  @doc """
  Find and decode the ECS option from an OPT record's options.

  ### Arguments

  * `options` is the list of `{code, binary}` tuples from the
    OPT record.

  ### Returns

  * `{:ok, %{family: 1 | 2, source_prefix: 0..128, scope_prefix: 0..128, address: tuple()}}`
    on success.
  * `:none` when no ECS option is present.
  * `{:error, :malformed}` when the option payload doesn't
    conform to RFC 7871 §6.

  ### Examples

      iex> ExDns.EDNSClientSubnet.find_in_options([])
      :none

  """
  @spec find_in_options([{non_neg_integer(), binary()}]) ::
          {:ok, map()} | :none | {:error, :malformed}
  def find_in_options(options) when is_list(options) do
    case List.keyfind(options, @option_code, 0) do
      nil -> :none
      {@option_code, data} -> decode(data)
    end
  end

  @doc false
  def decode(<<family::16, source_prefix::8, scope_prefix::8, addr_bytes::binary>>) do
    expected_addr_bytes = div(source_prefix + 7, 8)

    cond do
      family not in [1, 2] ->
        {:error, :malformed}

      family == 1 and source_prefix > 32 ->
        {:error, :malformed}

      family == 2 and source_prefix > 128 ->
        {:error, :malformed}

      byte_size(addr_bytes) != expected_addr_bytes ->
        {:error, :malformed}

      true ->
        {:ok,
         %{
           family: family,
           source_prefix: source_prefix,
           scope_prefix: scope_prefix,
           address: address_tuple(family, source_prefix, addr_bytes)
         }}
    end
  end

  def decode(_), do: {:error, :malformed}

  @doc """
  Encode an ECS option payload.

  ### Arguments

  * `family` is `1` (IPv4) or `2` (IPv6).
  * `source_prefix` is the bit count of the client subnet.
  * `scope_prefix` is the bit count the answer applies to. Use
    `0` in queries and in responses where the server isn't
    tailoring per-subnet.
  * `address` is the client address tuple.

  ### Returns

  * A `{8, payload_binary}` tuple ready to drop into an OPT
    record's `:options` list.

  ### Examples

      iex> ExDns.EDNSClientSubnet.encode_option(1, 24, 0, {192, 0, 2, 0})
      {8, <<0, 1, 24, 0, 192, 0, 2>>}

  """
  @spec encode_option(1 | 2, non_neg_integer(), non_neg_integer(), tuple()) ::
          {non_neg_integer(), binary()}
  def encode_option(family, source_prefix, scope_prefix, address)
      when family in [1, 2] and is_integer(source_prefix) and is_integer(scope_prefix) do
    addr_bytes = address_bytes(family, source_prefix, address)
    {@option_code, <<family::16, source_prefix::8, scope_prefix::8, addr_bytes::binary>>}
  end

  # ----- internals -------------------------------------------------

  defp address_bytes(1, source_prefix, {a, b, c, d}) do
    full = <<a, b, c, d>>
    take = div(source_prefix + 7, 8)
    binary_part(full, 0, take)
  end

  defp address_bytes(2, source_prefix, {a, b, c, d, e, f, g, h}) do
    full = <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
    take = div(source_prefix + 7, 8)
    binary_part(full, 0, take)
  end

  defp address_tuple(1, _source_prefix, addr_bytes) do
    padded = pad_to(addr_bytes, 4)
    <<a, b, c, d>> = padded
    {a, b, c, d}
  end

  defp address_tuple(2, _source_prefix, addr_bytes) do
    padded = pad_to(addr_bytes, 16)
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> = padded
    {a, b, c, d, e, f, g, h}
  end

  defp pad_to(bytes, target) when byte_size(bytes) >= target, do: binary_part(bytes, 0, target)

  defp pad_to(bytes, target) do
    bytes <> :binary.copy(<<0>>, target - byte_size(bytes))
  end
end
