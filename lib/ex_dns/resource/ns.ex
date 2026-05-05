defmodule ExDns.Resource.NS do
  @moduledoc """
  Manages the NS resource record (authoritative name server).

  The wire protocol is defined in [RFC1035](https://tools.ietf.org/html/rfc1035#section-3.3.11).

  ### NS RDATA format

      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      /                   NSDNAME                     /
      /                                               /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  Where `NSDNAME` is a domain name that should be authoritative for the
  specified class and domain. Internally the name is held as a dot-joined
  string (e.g. `"ns1.example.com"`).

  """

  @behaviour ExDns.Resource
  @behaviour ExDns.Resource.JSON

  defstruct [:name, :ttl, :class, :server]

  import ExDns.Resource.Validation
  alias ExDns.Message

  @doc """
  Returns an NS resource from a keyword list.

  ### Arguments

  * `resource` is a keyword list with `:server`, `:ttl`, `:class`, and
    `:name` keys.

  ### Returns

  * `{:ok, %ExDns.Resource.NS{}}` on success.

  * `{:error, {:ns, keyword_list_with_errors}}` if validation fails.

  """
  def new(resource) when is_list(resource) do
    resource
    |> validate_integer(:ttl)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  @doc """
  Decodes an NS record's RDATA into a struct.

  ### Arguments

  * `rdata` is the RDATA slice — a single domain name, possibly using
    compression pointers into `message`.

  * `message` is the enclosing DNS message, used to resolve compression
    pointers.

  ### Returns

  * `%ExDns.Resource.NS{}` with `server` set to the decoded name.

  ### Examples

      iex> ExDns.Resource.NS.decode(<<3, "ns1", 7, "example", 3, "com", 0>>, <<>>)
      %ExDns.Resource.NS{server: "ns1.example.com"}

  """
  @impl ExDns.Resource
  def decode(rdata, message) do
    {:ok, server, _rest} = Message.decode_name(rdata, message)
    %__MODULE__{server: server}
  end

  @doc """
  Encodes an NS struct into wire-format RDATA.

  ### Arguments

  * `resource` is an `%ExDns.Resource.NS{}`.

  ### Returns

  * The RDATA binary holding the encoded `NSDNAME`.

  ### Examples

      iex> ExDns.Resource.NS.encode(%ExDns.Resource.NS{server: "ns1.example.com"})
      <<3, "ns1", 7, "example", 3, "com", 0>>

  """
  @impl ExDns.Resource
  def encode(%__MODULE__{server: server}) do
    Message.encode_name(server)
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "NS"),
      ExDns.Resource.to_fqdn(resource.server)
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource) do
      ExDns.Resource.NS.format(resource)
    end
  end

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{server: target}) do
    %{"target" => trim_dot(target)}
  end

  @impl ExDns.Resource.JSON
  def decode_rdata(%{"target" => target}) when is_binary(target) do
    {:ok, %__MODULE__{server: target}}
  end

  def decode_rdata(_), do: {:error, :missing_target}

  defp trim_dot(nil), do: nil
  defp trim_dot(s) when is_binary(s), do: String.trim_trailing(s, ".")
end
