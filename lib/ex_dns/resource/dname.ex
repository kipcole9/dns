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
