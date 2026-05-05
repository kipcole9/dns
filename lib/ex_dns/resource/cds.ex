defmodule ExDns.Resource.CDS do
  @moduledoc """
  Child DS (CDS) record (RFC 7344) — type code 59.

  Wire-identical to `ExDns.Resource.DS`. Published in the *child*
  zone to signal to the parent which DS records the child wants
  the parent to publish during a KSK rollover. Parents that
  honour RFC 7344 / RFC 8078 poll for CDS and republish their DS
  set automatically.

  ### Special "delete" record

  RFC 8078 §4 defines a sentinel CDS that requests the parent to
  *remove* every DS for this zone:

      CDS  0 0 0 00

  i.e. key_tag=0, algorithm=0, digest_type=0, digest=`<<0>>`.
  Use `delete_record/2` to construct it.
  """

  @behaviour ExDns.Resource

  defstruct [:name, :ttl, :class, :key_tag, :algorithm, :digest_type, :digest]

  @impl ExDns.Resource
  def decode(rdata, _message) do
    <<key_tag::size(16), algorithm::size(8), digest_type::size(8), digest::binary>> = rdata

    %__MODULE__{
      key_tag: key_tag,
      algorithm: algorithm,
      digest_type: digest_type,
      digest: digest
    }
  end

  @impl ExDns.Resource
  def encode(%__MODULE__{} = record) do
    <<record.key_tag::size(16), record.algorithm::size(8), record.digest_type::size(8),
      record.digest::binary>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "CDS"),
      Integer.to_string(resource.key_tag),
      " ",
      Integer.to_string(resource.algorithm),
      " ",
      Integer.to_string(resource.digest_type),
      " ",
      Base.encode16(resource.digest, case: :lower)
    ]
  end

  @doc """
  Construct the RFC 8078 §4 sentinel CDS that asks the parent to
  remove every DS for `zone`.

  ### Arguments

  * `zone` — the zone apex.
  * `ttl` — TTL on the record. Defaults to `3600`.

  ### Returns

  * `%CDS{}` with all fields zeroed and digest = `<<0>>`.

  ### Examples

      iex> ExDns.Resource.CDS.delete_record("example.test").digest
      <<0>>

  """
  @spec delete_record(binary(), non_neg_integer()) :: %__MODULE__{}
  def delete_record(zone, ttl \\ 3600) do
    %__MODULE__{
      name: zone,
      ttl: ttl,
      class: :in,
      key_tag: 0,
      algorithm: 0,
      digest_type: 0,
      digest: <<0>>
    }
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.CDS.format(resource)
  end
end
