defmodule ExDns.Resource.CDNSKEY do
  @moduledoc """
  Child DNSKEY (CDNSKEY) record (RFC 7344) — type code 60.

  Wire-identical to `ExDns.Resource.DNSKEY`. Published in the
  *child* zone alongside `CDS` to give the parent a self-
  contained signal of "here is the key you should be making a DS
  for". Parents that honour RFC 8078 §3.1 may prefer CDNSKEY +
  compute the DS themselves rather than trusting the child's CDS
  digest choice.

  ### Special "delete" record

  RFC 8078 §4 defines a sentinel CDNSKEY that requests parent
  cleanup:

      CDNSKEY  0 3 0 AA==

  flags=0, protocol=3, algorithm=0, public_key=`<<0>>`.
  """

  @behaviour ExDns.Resource

  defstruct [:name, :ttl, :class, :flags, :protocol, :algorithm, :public_key]

  @impl ExDns.Resource
  def decode(rdata, _message) do
    <<flags::size(16), protocol::size(8), algorithm::size(8), public_key::binary>> = rdata

    %__MODULE__{
      flags: flags,
      protocol: protocol,
      algorithm: algorithm,
      public_key: public_key
    }
  end

  @impl ExDns.Resource
  def encode(%__MODULE__{} = record) do
    <<record.flags::size(16), record.protocol::size(8), record.algorithm::size(8),
      record.public_key::binary>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "CDNSKEY"),
      Integer.to_string(resource.flags),
      " ",
      Integer.to_string(resource.protocol),
      " ",
      Integer.to_string(resource.algorithm),
      " ",
      Base.encode64(resource.public_key)
    ]
  end

  @doc """
  Construct the RFC 8078 §4 sentinel CDNSKEY that asks the
  parent to remove every DS for `zone`.

  ### Arguments

  * `zone` — the zone apex.
  * `ttl` — TTL on the record. Defaults to `3600`.

  ### Returns

  * `%CDNSKEY{}` with the sentinel field values.

  ### Examples

      iex> ExDns.Resource.CDNSKEY.delete_record("example.test").public_key
      <<0>>

  """
  @spec delete_record(binary(), non_neg_integer()) :: %__MODULE__{}
  def delete_record(zone, ttl \\ 3600) do
    %__MODULE__{
      name: zone,
      ttl: ttl,
      class: :in,
      flags: 0,
      protocol: 3,
      algorithm: 0,
      public_key: <<0>>
    }
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.CDNSKEY.format(resource)
  end
end
