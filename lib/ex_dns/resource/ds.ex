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
  @behaviour ExDns.Resource.JSON

  defstruct [:name, :ttl, :class, :key_tag, :algorithm, :digest_type, :digest]

  import ExDns.Resource.Validation

  @doc """
  Builds a DS record from a parser-produced keyword list.
  Field shape: `:key_tag`, `:algorithm`, `:digest_type`,
  `:digest` (hex binary).
  """
  def new(resource) when is_list(resource) do
    resource
    |> validate_integer(:ttl)
    |> validate_integer(:key_tag)
    |> validate_integer(:algorithm)
    |> validate_integer(:digest_type)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

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

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{} = ds) do
    %{
      "key_tag" => ds.key_tag,
      "algorithm" => ds.algorithm,
      "digest_type" => ds.digest_type,
      "digest" => Base.encode16(ds.digest || <<>>, case: :lower)
    }
  end

  @impl ExDns.Resource.JSON
  def decode_rdata(%{
        "key_tag" => key_tag,
        "algorithm" => algorithm,
        "digest_type" => digest_type,
        "digest" => digest_hex
      })
      when is_integer(key_tag) and is_integer(algorithm) and is_integer(digest_type) and
             is_binary(digest_hex) do
    case Base.decode16(digest_hex, case: :mixed) do
      {:ok, digest} ->
        {:ok,
         %__MODULE__{
           key_tag: key_tag,
           algorithm: algorithm,
           digest_type: digest_type,
           digest: digest
         }}

      :error ->
        {:error, :invalid_digest_hex}
    end
  end

  def decode_rdata(_), do: {:error, :invalid_ds_rdata}
end
