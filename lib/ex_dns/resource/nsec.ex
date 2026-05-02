defmodule ExDns.Resource.NSEC do
  @moduledoc """
  Manages the NSEC DNSSEC resource record (RFC 4034 §4).

  Type code 47.

  ### NSEC RDATA format

      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Next Domain Name           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Type Bit Maps              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  This implementation surfaces the type bit maps as a raw binary; a
  pretty-printer for the bitmap windows is left as a follow-up. The
  byte sequence round-trips exactly so DNSSEC zones served from this
  library remain valid.

  """

  @behaviour ExDns.Resource

  defstruct [:name, :ttl, :class, :next_domain, :type_bit_maps]

  alias ExDns.Message

  @impl ExDns.Resource
  def decode(rdata, message) do
    {:ok, next_domain, after_name} = Message.decode_name(rdata, message)
    %__MODULE__{next_domain: next_domain, type_bit_maps: after_name}
  end

  @impl ExDns.Resource
  def encode(%__MODULE__{next_domain: next_domain, type_bit_maps: type_bit_maps}) do
    <<Message.encode_name(next_domain)::binary, type_bit_maps::binary>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "NSEC"),
      ExDns.Resource.to_fqdn(resource.next_domain),
      " ",
      Base.encode16(resource.type_bit_maps, case: :lower)
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.NSEC.format(resource)
  end
end
