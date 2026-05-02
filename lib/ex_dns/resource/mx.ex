defmodule ExDns.Resource.MX do
  @moduledoc """
  Manages the MX resource record (mail exchange).

  The wire protocol is defined in [RFC1035](https://tools.ietf.org/html/rfc1035#section-3.3.9).

  ### MX RDATA format

      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                  PREFERENCE                   |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      /                   EXCHANGE                    /
      /                                               /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  Where `PREFERENCE` is a 16-bit integer (lower values are preferred) and
  `EXCHANGE` is a domain name that names a host willing to act as a mail
  exchange for the owner.

  """

  @behaviour ExDns.Resource

  defstruct [:name, :ttl, :class, :priority, :server]

  import ExDns.Resource.Validation
  alias ExDns.Message

  @doc """
  Returns an MX resource from a keyword list.

  ### Arguments

  * `resource` is a keyword list with `:priority`, `:server`, `:ttl`,
    `:class`, and `:name` keys.

  ### Returns

  * `{:ok, %ExDns.Resource.MX{}}` on success.

  * `{:error, {:mx, keyword_list_with_errors}}` on validation failure.

  """
  def new(resource) when is_list(resource) do
    resource
    |> validate_integer(:ttl)
    |> validate_integer(:priority)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  @doc """
  Decodes an MX record's RDATA into a struct.

  ### Arguments

  * `rdata` is the RDATA slice — a 16-bit `PREFERENCE` followed by a
    domain name.

  * `message` is the enclosing DNS message, used to resolve compression
    pointers in `EXCHANGE`.

  ### Returns

  * `%ExDns.Resource.MX{}` with `priority` and `server` populated.

  ### Examples

      iex> ExDns.Resource.MX.decode(<<0, 10, 4, "mail", 7, "example", 3, "com", 0>>, <<>>)
      %ExDns.Resource.MX{priority: 10, server: "mail.example.com"}

  """
  @impl ExDns.Resource
  def decode(<<priority::size(16), exchange::binary>>, message) do
    {:ok, server, _rest} = Message.decode_name(exchange, message)
    %__MODULE__{priority: priority, server: server}
  end

  @doc """
  Encodes an MX struct into wire-format RDATA.

  ### Examples

      iex> ExDns.Resource.MX.encode(%ExDns.Resource.MX{priority: 10, server: "mail.example.com"})
      <<0, 10, 4, "mail", 7, "example", 3, "com", 0>>

  """
  @impl ExDns.Resource
  def encode(%__MODULE__{priority: priority, server: server}) do
    <<priority::size(16), Message.encode_name(server)::binary>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "MX"),
      Integer.to_string(resource.priority),
      " ",
      ExDns.Resource.to_fqdn(resource.server)
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource) do
      ExDns.Resource.MX.format(resource)
    end
  end
end
