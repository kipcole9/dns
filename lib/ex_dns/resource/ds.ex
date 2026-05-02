defmodule ExDns.Resource.DS do
  @moduledoc """
  Manages the DS (Delegation Signer) DNSSEC resource record (RFC 4034 §5).

  Type code 43.

  ### DS RDATA format

      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   Key Tag (16 bits)         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Algorithm | Digest Type |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Digest                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  This implementation parses and serialises DS records but does not
  validate the digest itself — DNSSEC verification is out of scope.

  """

  @behaviour ExDns.Resource

  defstruct [:name, :ttl, :class, :key_tag, :algorithm, :digest_type, :digest]

  @impl ExDns.Resource
  def decode(
        <<key_tag::size(16), algorithm::size(8), digest_type::size(8), digest::binary>>,
        _message
      ) do
    %__MODULE__{
      key_tag: key_tag,
      algorithm: algorithm,
      digest_type: digest_type,
      digest: digest
    }
  end

  @impl ExDns.Resource
  def encode(%__MODULE__{
        key_tag: key_tag,
        algorithm: algorithm,
        digest_type: digest_type,
        digest: digest
      }) do
    <<key_tag::size(16), algorithm::size(8), digest_type::size(8), digest::binary>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "DS"),
      Integer.to_string(resource.key_tag),
      " ",
      Integer.to_string(resource.algorithm),
      " ",
      Integer.to_string(resource.digest_type),
      " ",
      Base.encode16(resource.digest, case: :lower)
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.DS.format(resource)
  end
end
