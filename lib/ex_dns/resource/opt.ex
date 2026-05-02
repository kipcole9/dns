defmodule ExDns.Resource.OPT do
  @moduledoc """
  Implements the OPT pseudo-resource record used by EDNS(0).

  The wire protocol is defined in [RFC6891](https://tools.ietf.org/html/rfc6891).

  ## Wire layout

  The OPT record looks like a normal resource record but several of its
  fields are repurposed:

      +------------+--------------+------------------------------+
      | Field      | Type         | Description                  |
      +------------+--------------+------------------------------+
      | NAME       | domain name  | MUST be the root (`""`)      |
      | TYPE       | u16          | 41                           |
      | CLASS      | u16          | requestor's UDP payload size |
      | TTL        | u32          | ext-rcode (8) | version (8)  |
      |            |              | | DO (1) | Z (15)            |
      | RDLENGTH   | u16          | length of option list        |
      | RDATA      | option list  | zero or more {code, data}    |
      +------------+--------------+------------------------------+

  Each option in `RDATA` is `<<option_code::16, option_length::16,
  option_data::binary-size(option_length)>>`.

  Because the CLASS and TTL fields are repurposed, the `decode/2` and
  `encode/1` callbacks of `ExDns.Resource` are not appropriate here:
  the section codec (`ExDns.Message.RR`) special-cases TYPE 41 and
  calls `decode_record/4` / `encode_record/1` on this module instead.

  """

  defstruct payload_size: 4096,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: 0,
            z: 0,
            options: []

  @type option :: {non_neg_integer(), binary()}

  @type t :: %__MODULE__{
          payload_size: non_neg_integer(),
          extended_rcode: non_neg_integer(),
          version: non_neg_integer(),
          dnssec_ok: 0 | 1,
          z: non_neg_integer(),
          options: [option()]
        }

  @doc """
  Builds an OPT struct from the wire-level fields of a single resource
  record whose TYPE is 41.

  ### Arguments

  * `class_field` is the 16-bit CLASS, repurposed as the requestor's
    UDP payload size.

  * `ttl_field` is the 32-bit TTL, repurposed as
    `<<extended_rcode::8, version::8, dnssec_ok::1, z::15>>`.

  * `rdata` is the option list.

  * `_message` is unused (no name compression in OPT RDATA).

  ### Returns

  * `%ExDns.Resource.OPT{}`.

  """
  @spec decode_record(non_neg_integer(), non_neg_integer(), binary(), binary()) :: t()

  def decode_record(class_field, ttl_field, rdata, _message) do
    <<extended_rcode::size(8), version::size(8), dnssec_ok::size(1), z::size(15)>> =
      <<ttl_field::size(32)>>

    %__MODULE__{
      payload_size: class_field,
      extended_rcode: extended_rcode,
      version: version,
      dnssec_ok: dnssec_ok,
      z: z,
      options: decode_options(rdata, [])
    }
  end

  defp decode_options(<<>>, acc), do: Enum.reverse(acc)

  defp decode_options(
         <<code::size(16), length::size(16), data::binary-size(length), rest::binary>>,
         acc
       ) do
    decode_options(rest, [{code, data} | acc])
  end

  @doc """
  Encodes an OPT struct into a complete wire-format resource record
  (NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA).

  Returns a binary suitable for direct concatenation into the Additional
  section.
  """
  @spec encode_record(t()) :: binary()

  def encode_record(%__MODULE__{} = opt) do
    %__MODULE__{
      payload_size: payload_size,
      extended_rcode: extended_rcode,
      version: version,
      dnssec_ok: dnssec_ok,
      z: z,
      options: options
    } = opt

    rdata = encode_options(options)
    rdlength = byte_size(rdata)

    <<
      # NAME = root
      0::size(8),
      # TYPE = 41 (OPT)
      41::size(16),
      # CLASS = payload size
      payload_size::size(16),
      # TTL
      extended_rcode::size(8),
      version::size(8),
      dnssec_ok::size(1),
      z::size(15),
      # RDLENGTH + RDATA
      rdlength::size(16),
      rdata::binary
    >>
  end

  @doc """
  Encodes an option list into the binary form used in the OPT RDATA.
  """
  @spec encode_options([option()]) :: binary()

  def encode_options(options) when is_list(options) do
    options
    |> Enum.map(fn {code, data} ->
      <<code::size(16), byte_size(data)::size(16), data::binary>>
    end)
    |> IO.iodata_to_binary()
  end

  @doc """
  Convenience constructor: returns the typical "I am EDNS0-aware"
  OPT record a server includes in its responses, with the supplied
  payload size (default 4096).
  """
  @spec response_opt(keyword()) :: t()

  def response_opt(options \\ []) do
    %__MODULE__{
      payload_size: Keyword.get(options, :payload_size, 4096),
      extended_rcode: Keyword.get(options, :extended_rcode, 0),
      version: 0,
      dnssec_ok: Keyword.get(options, :dnssec_ok, 0),
      z: 0,
      options: Keyword.get(options, :options, [])
    }
  end
end
