defmodule ExDns.Resource.AAAA do
  @moduledoc """
  Manages the AAAA resource record (IPv6 host address).

  The wire protocol is defined in
  [RFC3596](https://tools.ietf.org/html/rfc3596#section-2.2). RDATA is a
  single 128-bit IPv6 address encoded as 16 octets in network byte order.

  Internally, the address is held as an `:inet`-style 8-tuple
  (`{a, b, c, d, e, f, g, h}` of 16-bit unsigned integers).

  """

  @behaviour ExDns.Resource

  defstruct [:name, :ttl, :class, :ipv6]

  import ExDns.Resource.Validation

  @doc """
  Returns an AAAA resource from a keyword list.

  ### Arguments

  * `resource` is a keyword list with `:ipv6`, `:ttl`, `:class`, and
    `:name` keys.

  ### Returns

  * `{:ok, %ExDns.Resource.AAAA{}}` on success.

  * `{:error, {:aaaa, keyword_list_with_errors}}` if validation fails.

  """
  def new(resource) do
    resource
    |> validate_ipv6(:ipv6)
    |> validate_integer(:ttl)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  @doc """
  Decodes an AAAA record's RDATA into a struct.

  ### Arguments

  * `rdata` is exactly 16 bytes — the IPv6 address in network byte order.

  * `_message` is unused (no name compression possible inside the RDATA).

  ### Returns

  * `%ExDns.Resource.AAAA{}` with `ipv6` set to an `:inet`-style
    8-tuple.

  ### Examples

      iex> ExDns.Resource.AAAA.decode(<<0x20, 0x01, 0x0d, 0xb8,
      ...>   0::16, 0::16, 0::16, 0::16, 0::16, 1::16>>, <<>>)
      %ExDns.Resource.AAAA{ipv6: {0x2001, 0x0db8, 0, 0, 0, 0, 0, 1}}

  """
  @impl ExDns.Resource
  def decode(<<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>, _message) do
    %__MODULE__{ipv6: {a, b, c, d, e, f, g, h}}
  end

  @doc """
  Encodes an AAAA struct into wire-format RDATA (16 bytes).

  ### Arguments

  * `resource` is an `%ExDns.Resource.AAAA{}`.

  ### Returns

  * The 16-byte RDATA binary.

  ### Examples

      iex> ExDns.Resource.AAAA.encode(%ExDns.Resource.AAAA{ipv6: {0x2001, 0x0db8, 0, 0, 0, 0, 0, 1}})
      <<0x20, 0x01, 0x0d, 0xb8, 0::16, 0::16, 0::16, 0::16, 0::16, 1::16>>

  """
  @impl ExDns.Resource
  def encode(%__MODULE__{ipv6: {a, b, c, d, e, f, g, h}}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "AAAA"),
      to_string(:inet.ntoa(resource.ipv6))
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource) do
      ExDns.Resource.AAAA.format(resource)
    end
  end
end
