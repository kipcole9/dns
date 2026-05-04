defmodule ExDns.Resource.TSIG do
  @moduledoc """
  Implements the TSIG pseudo-RR (RFC 8945) — Transaction SIGnature.

  TSIG appears as the **last** record in the Additional section. The
  record provides authentication and integrity for a DNS message via a
  shared-secret HMAC computed over the message bytes.

  ## Wire layout

      +------------+--------------+--------------------------------+
      | Field      | Type         | Description                    |
      +------------+--------------+--------------------------------+
      | NAME       | domain name  | the key name                   |
      | TYPE       | u16          | 250                            |
      | CLASS      | u16          | ANY (255)                      |
      | TTL        | u32          | 0                              |
      | RDLENGTH   | u16          | length of RDATA                |
      | RDATA      |              |                                |
      |   AlgName  | domain name  | e.g. "hmac-sha256."            |
      |   TimeSign | u48          | seconds since 1970-01-01       |
      |   Fudge    | u16          | allowed clock skew, seconds    |
      |   MACSize  | u16          | length of MAC, bytes           |
      |   MAC      | binary       | the HMAC                       |
      |   OrigID   | u16          | original message ID            |
      |   Error    | u16          | error code                     |
      |   OtherLen | u16          | length of OtherData            |
      |   OtherData| binary       | usually empty                  |
      +------------+--------------+--------------------------------+

  Like `ExDns.Resource.OPT`, the standard `decode/2` and `encode/1`
  callbacks of `ExDns.Resource` don't apply because the wire wrapping
  is repurposed (CLASS, TTL). The section codec
  (`ExDns.Message.RR`) special-cases TYPE 250 and calls
  `decode_record/4` / `encode_record/2` here.

  ## Algorithm names

  RFC 8945 §6.1 lists the standardised algorithms:

  * `"hmac-sha256."` — recommended default
  * `"hmac-sha384."`, `"hmac-sha512."`
  * `"hmac-sha224."`
  * `"hmac-sha1."` — legacy
  * `"hmac-md5.sig-alg.reg.int."` — deprecated, decode only

  We map the algorithm domain name (case-insensitive) to the
  corresponding `:crypto.hash_algorithm/0` atom for HMAC computation.

  """

  defstruct name: "",
            algorithm: "hmac-sha256.",
            time_signed: 0,
            fudge: 300,
            mac: <<>>,
            original_id: 0,
            error: 0,
            other_data: <<>>

  @type algorithm :: binary()

  @type t :: %__MODULE__{
          name: binary(),
          algorithm: algorithm(),
          time_signed: non_neg_integer(),
          fudge: non_neg_integer(),
          mac: binary(),
          original_id: non_neg_integer(),
          error: non_neg_integer(),
          other_data: binary()
        }

  alias ExDns.Message

  @doc """
  Decodes a TSIG record from the wire-level fields of a single record
  whose TYPE is 250.

  ### Arguments

  * `name` is the owner name (the TSIG key name).
  * `class_field` should be `255` (ANY); we don't enforce it.
  * `ttl_field` should be `0`; we don't enforce it.
  * `rdata` is the binary RDATA.
  * `message` is the enclosing message, used to resolve name pointers
    inside the algorithm name.

  ### Returns

  * `%ExDns.Resource.TSIG{}`.

  """
  @spec decode_record(binary(), non_neg_integer(), non_neg_integer(), binary(), binary()) :: t()
  def decode_record(name, _class_field, _ttl_field, rdata, message) do
    {:ok, algorithm, after_alg} = Message.decode_name(rdata, message)

    <<time_signed::size(48), fudge::size(16), mac_size::size(16), mac::binary-size(mac_size),
      original_id::size(16), error::size(16), other_len::size(16),
      other_data::binary-size(other_len)>> = after_alg

    %__MODULE__{
      name: name,
      algorithm: ensure_trailing_dot(algorithm),
      time_signed: time_signed,
      fudge: fudge,
      mac: mac,
      original_id: original_id,
      error: error,
      other_data: other_data
    }
  end

  @doc """
  Encodes a TSIG struct into a complete wire-format record (NAME +
  TYPE + CLASS + TTL + RDLENGTH + RDATA), suitable for direct
  concatenation into the Additional section.

  Per RFC 8945 §4.2: CLASS is always ANY (255), TTL is always 0.
  """
  @spec encode_record(t()) :: binary()
  def encode_record(%__MODULE__{} = tsig) do
    rdata = encode_rdata(tsig)
    rdlength = byte_size(rdata)

    <<
      Message.encode_name(tsig.name)::binary,
      # TYPE = 250 (TSIG)
      250::size(16),
      # CLASS = ANY (255)
      255::size(16),
      # TTL = 0
      0::size(32),
      rdlength::size(16),
      rdata::binary
    >>
  end

  @doc false
  def encode_rdata(%__MODULE__{} = tsig) do
    <<
      Message.encode_name(tsig.algorithm)::binary,
      tsig.time_signed::size(48),
      tsig.fudge::size(16),
      byte_size(tsig.mac)::size(16),
      tsig.mac::binary,
      tsig.original_id::size(16),
      tsig.error::size(16),
      byte_size(tsig.other_data)::size(16),
      tsig.other_data::binary
    >>
  end

  @doc """
  Returns the `:crypto`-recognised hash algorithm atom for a TSIG
  algorithm name. Domain names are compared case-insensitively per
  RFC 8945 §6.

  Raises `ArgumentError` for unknown algorithms.
  """
  @spec hash_algorithm(algorithm()) :: :crypto.hash_algorithm()
  def hash_algorithm(name) when is_binary(name) do
    case name |> String.downcase(:ascii) |> String.trim_trailing(".") do
      "hmac-sha256" -> :sha256
      "hmac-sha224" -> :sha224
      "hmac-sha384" -> :sha384
      "hmac-sha512" -> :sha512
      "hmac-sha1" -> :sha
      "hmac-md5.sig-alg.reg.int" -> :md5
      other -> raise ArgumentError, "Unknown TSIG algorithm: #{inspect(other)}"
    end
  end

  defp ensure_trailing_dot(""), do: ""
  defp ensure_trailing_dot(name) do
    if String.ends_with?(name, "."), do: name, else: name <> "."
  end
end
