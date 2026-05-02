defmodule ExDns.Resource.TLSA do
  @moduledoc """
  Manages the TLSA (DANE) resource record (RFC 6698).

  Type code 52.

  ### TLSA RDATA format

      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Cert Usage    | Selector |
      | Matching Type |
      | Cert Association Data    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  * `cert_usage` (8 bits): 0 PKIX-TA, 1 PKIX-EE, 2 DANE-TA, 3 DANE-EE.
  * `selector` (8 bits): 0 Cert, 1 SPKI.
  * `matching_type` (8 bits): 0 Full, 1 SHA-256, 2 SHA-512.
  * `cert_data` (variable): the certificate-association data.

  """

  @behaviour ExDns.Resource

  defstruct [:name, :ttl, :class, :cert_usage, :selector, :matching_type, :cert_data]

  @impl ExDns.Resource
  def decode(
        <<cert_usage::size(8), selector::size(8), matching_type::size(8), cert_data::binary>>,
        _message
      ) do
    %__MODULE__{
      cert_usage: cert_usage,
      selector: selector,
      matching_type: matching_type,
      cert_data: cert_data
    }
  end

  @impl ExDns.Resource
  def encode(%__MODULE__{
        cert_usage: cert_usage,
        selector: selector,
        matching_type: matching_type,
        cert_data: cert_data
      }) do
    <<cert_usage::size(8), selector::size(8), matching_type::size(8), cert_data::binary>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "TLSA"),
      Integer.to_string(resource.cert_usage),
      " ",
      Integer.to_string(resource.selector),
      " ",
      Integer.to_string(resource.matching_type),
      " ",
      Base.encode16(resource.cert_data, case: :lower)
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.TLSA.format(resource)
  end
end
