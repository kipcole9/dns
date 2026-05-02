defmodule ExDns.Resource.DNSKEY do
  @moduledoc """
  Manages the DNSKEY DNSSEC resource record (RFC 4034 §2).

  Type code 48.

  ### DNSKEY RDATA format

      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |    Flags (16 bits)          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Protocol | Algorithm |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |    Public Key                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  This implementation parses and serialises DNSKEY records but does not
  use the key — DNSSEC signing/verification is out of scope.

  """

  @behaviour ExDns.Resource

  defstruct [:name, :ttl, :class, :flags, :protocol, :algorithm, :public_key]

  @impl ExDns.Resource
  def decode(
        <<flags::size(16), protocol::size(8), algorithm::size(8), public_key::binary>>,
        _message
      ) do
    %__MODULE__{
      flags: flags,
      protocol: protocol,
      algorithm: algorithm,
      public_key: public_key
    }
  end

  @impl ExDns.Resource
  def encode(%__MODULE__{
        flags: flags,
        protocol: protocol,
        algorithm: algorithm,
        public_key: public_key
      }) do
    <<flags::size(16), protocol::size(8), algorithm::size(8), public_key::binary>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "DNSKEY"),
      Integer.to_string(resource.flags),
      " ",
      Integer.to_string(resource.protocol),
      " ",
      Integer.to_string(resource.algorithm),
      " ",
      Base.encode64(resource.public_key)
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.DNSKEY.format(resource)
  end
end
