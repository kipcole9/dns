defmodule ExDns.Resource.TXT do
  @moduledoc """
  Manages the TXT resource record (free-form text).

  The wire protocol is defined in [RFC1035](https://tools.ietf.org/html/rfc1035#section-3.3.14).

  ### TXT RDATA format

      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      /                   TXT-DATA                    /
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

  The RDATA is one or more `<character-string>`s. A `<character-string>`
  is a single length octet (0-255) followed by that number of octets of
  data. Multiple character strings may appear in a single TXT record;
  this implementation surfaces them as a list of binaries in the
  `:strings` field.

  """

  @behaviour ExDns.Resource

  defstruct [:name, :ttl, :class, strings: []]

  @doc """
  Decodes a TXT record's RDATA into a struct.

  ### Arguments

  * `rdata` is the entire RDATA slice — a sequence of length-prefixed
    character strings.

  * `_message` is unused (no name compression in TXT RDATA).

  ### Returns

  * `%ExDns.Resource.TXT{}` with `strings` populated as a list of
    binaries in the order they appeared on the wire.

  ### Examples

      iex> ExDns.Resource.TXT.decode(<<5, "hello", 5, "world">>, <<>>)
      %ExDns.Resource.TXT{strings: ["hello", "world"]}

      iex> ExDns.Resource.TXT.decode(<<>>, <<>>)
      %ExDns.Resource.TXT{strings: []}

  """
  @impl ExDns.Resource
  def decode(rdata, _message) when is_binary(rdata) do
    %__MODULE__{strings: decode_strings(rdata, [])}
  end

  defp decode_strings(<<>>, acc), do: Enum.reverse(acc)

  defp decode_strings(<<len, string::binary-size(len), rest::binary>>, acc) do
    decode_strings(rest, [string | acc])
  end

  @doc """
  Encodes a TXT struct into wire-format RDATA.

  Each entry in `:strings` becomes one length-prefixed character string.

  ### Examples

      iex> ExDns.Resource.TXT.encode(%ExDns.Resource.TXT{strings: ["hello", "world"]})
      <<5, "hello", 5, "world">>

      iex> ExDns.Resource.TXT.encode(%ExDns.Resource.TXT{strings: []})
      <<>>

  """
  @impl ExDns.Resource
  def encode(%__MODULE__{strings: strings}) do
    strings
    |> Enum.map(fn string -> <<byte_size(string)::size(8), string::binary>> end)
    |> IO.iodata_to_binary()
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    quoted =
      resource.strings
      |> Enum.map(fn string -> [?", string, ?"] end)
      |> Enum.intersperse(?\s)

    [ExDns.Resource.format_preamble(resource, "TXT"), quoted]
  end

  defimpl ExDns.Resource.Format do
    def format(resource) do
      ExDns.Resource.TXT.format(resource)
    end
  end
end
