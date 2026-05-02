defmodule ExDns.Resource.CNAME do
  @moduledoc """
  Manages the CNAME resource record (canonical name alias).

  The wire protocol is defined in [RFC1035](https://tools.ietf.org/html/rfc1035#section-3.3.1).

  ### CNAME RDATA format

      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      /                     CNAME                     /
      /                                               /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  Where `CNAME` is a domain name that specifies the canonical or primary
  name for the owner; the owner is an alias.

  """

  @behaviour ExDns.Resource

  defstruct [:name, :ttl, :class, :server]

  import ExDns.Resource.Validation
  alias ExDns.Message

  @doc """
  Returns a CNAME resource from a keyword list.

  ### Arguments

  * `resource` is a keyword list with `:server` (the canonical name),
    `:ttl`, `:class`, and `:name` keys.

  ### Returns

  * `{:ok, %ExDns.Resource.CNAME{}}` on success.

  * `{:error, {:cname, keyword_list_with_errors}}` on validation failure.

  """
  def new(resource) do
    resource
    |> validate_integer(:ttl)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  @doc """
  Decodes a CNAME record's RDATA into a struct.

  ### Arguments

  * `rdata` is the RDATA slice — a single domain name, possibly using
    compression pointers into `message`.

  * `message` is the enclosing DNS message, used to resolve compression
    pointers.

  ### Returns

  * `%ExDns.Resource.CNAME{}` with `server` set to the canonical name.

  ### Examples

      iex> ExDns.Resource.CNAME.decode(<<3, "www", 7, "example", 3, "com", 0>>, <<>>)
      %ExDns.Resource.CNAME{server: "www.example.com"}

  """
  @impl ExDns.Resource
  def decode(rdata, message) do
    {:ok, server, _rest} = Message.decode_name(rdata, message)
    %__MODULE__{server: server}
  end

  @doc """
  Encodes a CNAME struct into wire-format RDATA.

  ### Examples

      iex> ExDns.Resource.CNAME.encode(%ExDns.Resource.CNAME{server: "www.example.com"})
      <<3, "www", 7, "example", 3, "com", 0>>

  """
  @impl ExDns.Resource
  def encode(%__MODULE__{server: server}) do
    Message.encode_name(server)
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "CNAME"),
      ExDns.Resource.to_fqdn(resource.server)
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource) do
      ExDns.Resource.CNAME.format(resource)
    end
  end
end
