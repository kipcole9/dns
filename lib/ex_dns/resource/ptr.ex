defmodule ExDns.Resource.PTR do
  @moduledoc """
  Manages the PTR resource record (domain-name pointer, used for reverse
  DNS).

  The wire protocol is defined in [RFC1035](https://tools.ietf.org/html/rfc1035#section-3.3.12).

  ### PTR RDATA format

      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      /                   PTRDNAME                    /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  Where `PTRDNAME` is a domain name that points to some location in the
  domain-name space. Unlike CNAME, PTR does not imply any alias chasing.

  """

  @behaviour ExDns.Resource
  @behaviour ExDns.Resource.JSON

  defstruct [:name, :ttl, :class, :pointer]

  alias ExDns.Message

  import ExDns.Resource.Validation

  @doc """
  Builds a PTR record from a parser-produced keyword list.

  ### Arguments

  * `resource` is a keyword list with `:name`, optional
    `:ttl` and `:class`, plus either `:pointer` or `:server`
    (the zone-file grammar uses `server`, callers wiring
    this up directly may use `pointer`).

  ### Returns

  * `{:ok, %ExDns.Resource.PTR{}}` on success.

  * `{:error, {:ptr, keyword_list_with_errors}}` on
    validation failure.

  """
  def new(resource) when is_list(resource) do
    resource
    |> rename(:server, :pointer)
    |> validate_integer(:ttl)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  defp rename(resource, from, to) do
    case Keyword.pop(resource, from) do
      {nil, _} -> resource
      {value, rest} -> Keyword.put(rest, to, value)
    end
  end

  @doc """
  Decodes a PTR record's RDATA into a struct.

  ### Arguments

  * `rdata` is the RDATA slice — a single domain name, possibly using
    compression pointers into `message`.

  * `message` is the enclosing DNS message, used to resolve compression
    pointers.

  ### Returns

  * `%ExDns.Resource.PTR{}` with `pointer` set to the decoded name.

  ### Examples

      iex> ExDns.Resource.PTR.decode(<<3, "www", 7, "example", 3, "com", 0>>, <<>>)
      %ExDns.Resource.PTR{pointer: "www.example.com"}

  """
  @impl ExDns.Resource
  def decode(rdata, message) do
    {:ok, pointer, _rest} = Message.decode_name(rdata, message)
    %__MODULE__{pointer: pointer}
  end

  @doc """
  Encodes a PTR struct into wire-format RDATA.

  ### Examples

      iex> ExDns.Resource.PTR.encode(%ExDns.Resource.PTR{pointer: "host.example"})
      <<4, "host", 7, "example", 0>>

  """
  @impl ExDns.Resource
  def encode(%__MODULE__{pointer: pointer}) do
    Message.encode_name(pointer)
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "PTR"),
      ExDns.Resource.to_fqdn(resource.pointer)
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource) do
      ExDns.Resource.PTR.format(resource)
    end
  end

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{pointer: pointer}) do
    %{"pointer" => trim_dot(pointer)}
  end

  @impl ExDns.Resource.JSON
  def decode_rdata(%{"pointer" => pointer}) when is_binary(pointer) do
    {:ok, %__MODULE__{pointer: pointer}}
  end

  def decode_rdata(_), do: {:error, :missing_pointer}

  defp trim_dot(nil), do: nil
  defp trim_dot(s) when is_binary(s), do: String.trim_trailing(s, ".")
end
