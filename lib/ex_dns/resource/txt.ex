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
  @behaviour ExDns.Resource.JSON

  defstruct [:name, :ttl, :class, strings: []]

  import ExDns.Resource.Validation

  @doc """
  Builds a TXT record from a parser-produced keyword list.

  ### Arguments

  * `resource` is a keyword list with at least `:name`, plus
    optional `:ttl`, `:class`, and one of:

    * `:text` — a single character-string (the
      `quoted_texts -> quoted_text` grammar branch).

    * `:strings` — an explicit list of character-strings,
      for callers wiring this up from somewhere other than
      the zone parser.

  ### Returns

  * `{:ok, %ExDns.Resource.TXT{}}` on success.

  * `{:error, {:txt, keyword_list_with_errors}}` if validation
    fails.

  """
  def new(resource) when is_list(resource) do
    resource
    |> coerce_strings()
    |> validate_integer(:ttl)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  # The TXT grammar emits one of:
  #   * `{:text, "single"}` — a single quoted_text. The value
  #     comes from the lexer's `strip_quote/1` which returns
  #     an Erlang charlist; we coerce to a binary.
  #   * `[{:text, "a"}, {:text, "b"} | …]` — multiple quoted_texts
  #     (the recursive yecc rule produces a nested tuple-of-list).
  #   * `{:strings, [binary, …]}` — for callers wiring this up
  #     from somewhere other than the zone parser.
  # All three forms collapse into a `:strings` list of binaries.
  defp coerce_strings(resource) do
    {strings_keys, rest} = Keyword.split(resource, [:text, :strings])

    flattened =
      strings_keys
      |> Enum.flat_map(fn
        {:text, s} -> [to_binary(s)]
        {:strings, list} when is_list(list) -> Enum.map(list, &to_binary/1)
        _ -> []
      end)

    Keyword.put(rest, :strings, flattened)
  end

  defp to_binary(s) when is_binary(s), do: s
  defp to_binary(s) when is_list(s), do: List.to_string(s)

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

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{strings: strings}) do
    %{"strings" => strings || []}
  end

  @impl ExDns.Resource.JSON
  def decode_rdata(%{"strings" => strings}) when is_list(strings) do
    if Enum.all?(strings, &is_binary/1) do
      {:ok, %__MODULE__{strings: strings}}
    else
      {:error, :strings_must_be_binaries}
    end
  end

  def decode_rdata(_), do: {:error, :missing_strings}
end
