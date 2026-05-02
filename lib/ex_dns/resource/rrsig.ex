defmodule ExDns.Resource.RRSIG do
  @moduledoc """
  Manages the RRSIG DNSSEC resource record (RFC 4034 §3).

  Type code 46.

  ### RRSIG RDATA format

      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Type Covered (16 bits)     |
      | Algorithm | Labels |
      | Original TTL (32 bits)     |
      | Sig Expiration (32 bits)   |
      | Sig Inception (32 bits)    |
      | Key Tag (16 bits)          |
      | Signer Name (variable)     |
      | Signature (variable)       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  This implementation parses and serialises RRSIG records but does not
  validate the signature — DNSSEC verification is out of scope.

  """

  @behaviour ExDns.Resource

  defstruct [
    :name,
    :ttl,
    :class,
    :type_covered,
    :algorithm,
    :labels,
    :original_ttl,
    :signature_expiration,
    :signature_inception,
    :key_tag,
    :signer,
    :signature
  ]

  alias ExDns.Message
  alias ExDns.Resource

  @impl Resource
  def decode(rdata, message) do
    <<type_covered::size(16), algorithm::size(8), labels::size(8), original_ttl::size(32),
      signature_expiration::size(32), signature_inception::size(32), key_tag::size(16),
      signer_and_sig::binary>> = rdata

    {:ok, signer, after_signer} = Message.decode_name(signer_and_sig, message)

    %__MODULE__{
      type_covered: Resource.decode_type(type_covered),
      algorithm: algorithm,
      labels: labels,
      original_ttl: original_ttl,
      signature_expiration: signature_expiration,
      signature_inception: signature_inception,
      key_tag: key_tag,
      signer: signer,
      signature: after_signer
    }
  end

  @impl Resource
  def encode(%__MODULE__{
        type_covered: type_covered,
        algorithm: algorithm,
        labels: labels,
        original_ttl: original_ttl,
        signature_expiration: signature_expiration,
        signature_inception: signature_inception,
        key_tag: key_tag,
        signer: signer,
        signature: signature
      }) do
    <<Resource.type_from(type_covered)::size(16), algorithm::size(8), labels::size(8),
      original_ttl::size(32), signature_expiration::size(32), signature_inception::size(32),
      key_tag::size(16), Message.encode_name(signer)::binary, signature::binary>>
  end

  @impl Resource
  def format(%__MODULE__{} = resource) do
    [
      Resource.format_preamble(resource, "RRSIG"),
      Atom.to_string(resource.type_covered) |> String.upcase(),
      " ",
      Integer.to_string(resource.algorithm),
      " ",
      Integer.to_string(resource.labels),
      " ",
      Integer.to_string(resource.original_ttl),
      " ",
      Integer.to_string(resource.signature_expiration),
      " ",
      Integer.to_string(resource.signature_inception),
      " ",
      Integer.to_string(resource.key_tag),
      " ",
      Resource.to_fqdn(resource.signer),
      " ",
      Base.encode64(resource.signature)
    ]
  end

  defimpl Resource.Format do
    def format(resource), do: ExDns.Resource.RRSIG.format(resource)
  end
end
