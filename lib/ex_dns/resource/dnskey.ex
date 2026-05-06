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
  @behaviour ExDns.Resource.JSON

  defstruct [:name, :ttl, :class, :flags, :protocol, :algorithm, :public_key]

  import ExDns.Resource.Validation

  @doc """
  Builds a DNSKEY record from a parser-produced keyword
  list. The `:public_key` field carries the base64-encoded
  key material as the operator typed it; downstream
  signers/validators decode as needed.
  """
  def new(resource) when is_list(resource) do
    resource
    |> validate_integer(:ttl)
    |> validate_integer(:flags)
    |> validate_integer(:protocol)
    |> validate_integer(:algorithm)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

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

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{} = key) do
    %{
      "flags" => key.flags,
      "protocol" => key.protocol,
      "algorithm" => key.algorithm,
      "public_key" => Base.encode64(key.public_key || <<>>)
    }
  end

  @impl ExDns.Resource.JSON
  def decode_rdata(%{
        "flags" => flags,
        "protocol" => protocol,
        "algorithm" => algorithm,
        "public_key" => public_key_b64
      })
      when is_integer(flags) and is_integer(protocol) and is_integer(algorithm) and
             is_binary(public_key_b64) do
    case Base.decode64(public_key_b64) do
      {:ok, public_key} ->
        {:ok,
         %__MODULE__{
           flags: flags,
           protocol: protocol,
           algorithm: algorithm,
           public_key: public_key
         }}

      :error ->
        {:error, :invalid_public_key_base64}
    end
  end

  def decode_rdata(_), do: {:error, :invalid_dnskey_rdata}
end
