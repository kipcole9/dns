defmodule ExDns.Resource.SSHFP do
  @moduledoc """
  Manages the SSHFP (SSH Key Fingerprint) resource record (RFC 4255).

  Type code 44.

  ### SSHFP RDATA format

      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Algorithm  | Fp Type |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Fingerprint                |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  * `algorithm` (8 bits): 1 RSA, 2 DSA, 3 ECDSA, 4 Ed25519, 6 Ed448.
  * `fp_type` (8 bits): 1 SHA-1, 2 SHA-256.
  * `fingerprint` (variable): the binary fingerprint of the key.

  """

  @behaviour ExDns.Resource
  @behaviour ExDns.Resource.JSON

  defstruct [:name, :ttl, :class, :algorithm, :fp_type, :fingerprint]

  @doc """
  Decodes an SSHFP RDATA into a struct.

  ### Examples

      iex> ExDns.Resource.SSHFP.decode(<<4, 2, 0xDE, 0xAD, 0xBE, 0xEF>>, <<>>)
      %ExDns.Resource.SSHFP{algorithm: 4, fp_type: 2, fingerprint: <<0xDE, 0xAD, 0xBE, 0xEF>>}

  """
  @impl ExDns.Resource
  def decode(<<algorithm::size(8), fp_type::size(8), fingerprint::binary>>, _message) do
    %__MODULE__{algorithm: algorithm, fp_type: fp_type, fingerprint: fingerprint}
  end

  @doc """
  Encodes an SSHFP into RDATA.

  ### Examples

      iex> ExDns.Resource.SSHFP.encode(%ExDns.Resource.SSHFP{algorithm: 4, fp_type: 2, fingerprint: <<1, 2, 3>>})
      <<4, 2, 1, 2, 3>>

  """
  @impl ExDns.Resource
  def encode(%__MODULE__{algorithm: algorithm, fp_type: fp_type, fingerprint: fingerprint}) do
    <<algorithm::size(8), fp_type::size(8), fingerprint::binary>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "SSHFP"),
      Integer.to_string(resource.algorithm),
      " ",
      Integer.to_string(resource.fp_type),
      " ",
      Base.encode16(resource.fingerprint, case: :lower)
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.SSHFP.format(resource)
  end

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{} = sshfp) do
    %{
      "algorithm" => sshfp.algorithm,
      "fingerprint_type" => sshfp.fp_type,
      "fingerprint" => Base.encode16(sshfp.fingerprint || <<>>, case: :lower)
    }
  end

  @impl ExDns.Resource.JSON
  def decode_rdata(%{
        "algorithm" => algorithm,
        "fingerprint_type" => fp_type,
        "fingerprint" => fp_hex
      })
      when is_integer(algorithm) and is_integer(fp_type) and is_binary(fp_hex) do
    case Base.decode16(fp_hex, case: :mixed) do
      {:ok, fp} -> {:ok, %__MODULE__{algorithm: algorithm, fp_type: fp_type, fingerprint: fp}}
      :error -> {:error, :invalid_fingerprint_hex}
    end
  end

  def decode_rdata(_), do: {:error, :invalid_sshfp_rdata}
end
