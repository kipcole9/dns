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

  defstruct [:name, :ttl, :class, :pointer]

  alias ExDns.Message

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
end
