defmodule ExDns.Resource.DNAME do
  @moduledoc """
  Manages the DNAME resource record (RFC 6672).

  Type code 39. RDATA is a single uncompressible domain name (the
  "DNAME target") that maps an entire subtree of names from the owner
  name to the target.

  Unlike CNAME, DNAME applies to descendants of the owner, not the
  owner itself. The wire format is identical to CNAME — just one name.
  RFC 6672 §2.4 forbids using compression in this RDATA on encode (the
  decoder must still tolerate pointers).

  """

  @behaviour ExDns.Resource

  defstruct [:name, :ttl, :class, :target]

  alias ExDns.Message

  import ExDns.Resource.Validation

  @doc """
  Builds a DNAME record from a parser-produced keyword list.

  ### Arguments

  * `resource` is a keyword list with `:name`, optional
    `:ttl` and `:class`, plus either `:target` or `:server`.

  ### Returns

  * `{:ok, %ExDns.Resource.DNAME{}}` on success.

  * `{:error, {:dname, keyword_list_with_errors}}` on
    validation failure.

  """
  def new(resource) when is_list(resource) do
    resource
    |> rename(:server, :target)
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
  Decodes a DNAME RDATA into a struct.

  ### Examples

      iex> ExDns.Resource.DNAME.decode(<<3, "new", 7, "example", 0>>, <<>>)
      %ExDns.Resource.DNAME{target: "new.example"}

  """
  @impl ExDns.Resource
  def decode(rdata, message) do
    {:ok, target, _rest} = Message.decode_name(rdata, message)
    %__MODULE__{target: target}
  end

  @doc """
  Encodes a DNAME struct into RDATA.

  ### Examples

      iex> ExDns.Resource.DNAME.encode(%ExDns.Resource.DNAME{target: "new.example"})
      <<3, "new", 7, "example", 0>>

  """
  @impl ExDns.Resource
  def encode(%__MODULE__{target: target}), do: Message.encode_name(target)

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "DNAME"),
      ExDns.Resource.to_fqdn(resource.target)
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.DNAME.format(resource)
  end
end
