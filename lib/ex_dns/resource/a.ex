defmodule ExDns.Resource.A do
  @moduledoc """
  Manages the A resource record (IPv4 host address).

  The wire protocol is defined in [RFC1035](https://tools.ietf.org/html/rfc1035#section-3.4.1).

  ### A RDATA format

      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    ADDRESS                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  Where `ADDRESS` is a 32-bit Internet address. Hosts that have multiple
  Internet addresses will have multiple A records.

  Internally, the address is held as an `:inet`-style tuple
  (`{a, b, c, d}`).

  """

  @behaviour ExDns.Resource

  defstruct [:name, :ttl, :class, :ipv4]

  import ExDns.Resource.Validation
  alias ExDns.Inet.Ipv4

  @doc """
  Returns an A resource from a keyword list (typically the output of the
  zone-file parser).

  ### Arguments

  * `resource` is a keyword list with `:ipv4`, `:ttl`, `:class`, and
    `:name` keys.

  ### Returns

  * `{:ok, %ExDns.Resource.A{}}` on success.

  * `{:error, {:a, keyword_list_with_errors}}` if validation fails.

  """
  def new(resource) when is_list(resource) do
    resource
    |> validate_ipv4(:ipv4)
    |> validate_integer(:ttl)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  @doc """
  Decodes an A record's RDATA into a struct.

  ### Arguments

  * `rdata` is exactly four bytes — the IPv4 address in network byte
    order.

  * `_message` is unused for A records (no name compression possible
    inside the RDATA).

  ### Returns

  * `%ExDns.Resource.A{}` with `ipv4` set to an `{a, b, c, d}` tuple.

  ### Examples

      iex> ExDns.Resource.A.decode(<<192, 0, 2, 1>>, <<>>)
      %ExDns.Resource.A{ipv4: {192, 0, 2, 1}}

  """
  @impl ExDns.Resource
  def decode(<<a, b, c, d>>, _message) do
    %__MODULE__{ipv4: {a, b, c, d}}
  end

  @doc """
  Encodes an A struct into wire-format RDATA (4 bytes).

  ### Arguments

  * `resource` is an `%ExDns.Resource.A{}`.

  ### Returns

  * The 4-byte RDATA binary.

  ### Examples

      iex> ExDns.Resource.A.encode(%ExDns.Resource.A{ipv4: {192, 0, 2, 1}})
      <<192, 0, 2, 1>>

  """
  @impl ExDns.Resource
  def encode(%__MODULE__{ipv4: {a, b, c, d}}) do
    <<a, b, c, d>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [ExDns.Resource.format_preamble(resource, "A"), Ipv4.to_string(resource.ipv4)]
  end

  defimpl ExDns.Resource.Format do
    def format(resource) do
      ExDns.Resource.A.format(resource)
    end
  end
end
