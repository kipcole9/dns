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
  @behaviour ExDns.Resource.JSON

  defstruct [:name, :ttl, :class, :cert_usage, :selector, :matching_type, :cert_data]

  import ExDns.Resource.Validation

  @doc """
  Builds a TLSA record from a parser-produced keyword list.

  ### Arguments

  * `resource` is a keyword list with `:name`, optional
    `:ttl` and `:class`, plus `:usage` (or `:cert_usage`),
    `:selector`, `:matching_type`, and `:data` (or
    `:cert_data`) — a hex string per RFC 6698.

  ### Returns

  * `{:ok, %ExDns.Resource.TLSA{}}` on success.

  * `{:error, {:tlsa, keyword_list_with_errors}}` on
    validation failure.

  """
  def new(resource) when is_list(resource) do
    resource
    |> rename(:usage, :cert_usage)
    |> rename(:data, :cert_data)
    |> validate_integer(:ttl)
    |> validate_integer(:cert_usage)
    |> validate_integer(:selector)
    |> validate_integer(:matching_type)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  defp rename(resource, from, to) do
    case Keyword.pop(resource, from) do
      {nil, _} -> resource
      {value, rest} -> Keyword.put(rest, to, value)
    end
  end

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

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{} = tlsa) do
    %{
      "usage" => tlsa.cert_usage,
      "selector" => tlsa.selector,
      "matching" => tlsa.matching_type,
      "data" => Base.encode16(tlsa.cert_data || <<>>, case: :lower)
    }
  end

  @impl ExDns.Resource.JSON
  def decode_rdata(%{
        "usage" => usage,
        "selector" => selector,
        "matching" => matching,
        "data" => data_hex
      })
      when is_integer(usage) and is_integer(selector) and is_integer(matching) and
             is_binary(data_hex) do
    case Base.decode16(data_hex, case: :mixed) do
      {:ok, data} ->
        {:ok,
         %__MODULE__{
           cert_usage: usage,
           selector: selector,
           matching_type: matching,
           cert_data: data
         }}

      :error ->
        {:error, :invalid_data_hex}
    end
  end

  def decode_rdata(_), do: {:error, :invalid_tlsa_rdata}
end
