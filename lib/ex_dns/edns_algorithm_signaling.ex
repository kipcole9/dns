defmodule ExDns.EDNSAlgorithmSignaling do
  @moduledoc """
  Signaling Cryptographic Algorithm Understanding in DNSSEC
  (RFC 6975).

  Defines three EDNS(0) options the resolver attaches to its
  outbound queries to tell the authoritative server which
  algorithms it understands. The server can use this to
  preferentially return signatures the resolver can actually
  validate, particularly during multi-algorithm rollovers.

  | Option | Code | Semantic                                 |
  |--------|------|------------------------------------------|
  | DAU    |  5   | DNSSEC Algorithm Understood              |
  | DHU    |  6   | DS Hash Understood                       |
  | N3U    |  7   | NSEC3 Hash Understood                    |

  Each option's value is a sequence of single-byte algorithm
  numbers — no length prefix, no padding.

  ## API

  * `encode_option/2` — build a `{code, payload}` ready for
    insertion into an OPT record's `:options` list.

  * `find_in_options/1` — extract whichever of the three
    options is present from an OPT's `:options` list.

  * `supported/1` — what we, ExDns, currently support for each
    of the three categories. Used both when building outbound
    queries (in recursor mode) and when surfacing capability in
    the admin UI.
  """

  @dau 5
  @dhu 6
  @n3u 7

  @doc """
  Returns the IANA option code for one of the three signaling
  options.

  ### Examples

      iex> ExDns.EDNSAlgorithmSignaling.option_code(:dau)
      5

  """
  @spec option_code(:dau | :dhu | :n3u) :: 5 | 6 | 7
  def option_code(:dau), do: @dau
  def option_code(:dhu), do: @dhu
  def option_code(:n3u), do: @n3u

  @doc """
  Encode a list of algorithm numbers as one of the three
  signaling options.

  ### Arguments

  * `kind` — `:dau`, `:dhu`, or `:n3u`.
  * `algorithms` — list of single-byte algorithm numbers.

  ### Returns

  * `{option_code, payload_binary}` ready to drop into an OPT
    record's `:options` list.

  ### Examples

      iex> ExDns.EDNSAlgorithmSignaling.encode_option(:dau, [8, 13, 15])
      {5, <<8, 13, 15>>}

  """
  @spec encode_option(:dau | :dhu | :n3u, [non_neg_integer()]) ::
          {non_neg_integer(), binary()}
  def encode_option(kind, algorithms) when is_list(algorithms) do
    payload =
      algorithms
      |> Enum.map(&<<&1::8>>)
      |> IO.iodata_to_binary()

    {option_code(kind), payload}
  end

  @doc """
  Decode the option's payload back into a list of algorithm
  numbers.

  ### Arguments

  * `payload` — the `{option_code, payload}` value half from
    an OPT record.

  ### Returns

  * `[non_neg_integer()]`.

  ### Examples

      iex> ExDns.EDNSAlgorithmSignaling.decode_payload(<<8, 13, 15>>)
      [8, 13, 15]

  """
  @spec decode_payload(binary()) :: [non_neg_integer()]
  def decode_payload(payload) when is_binary(payload) do
    for <<n::8 <- payload>>, do: n
  end

  @doc """
  Search an OPT options list for any of the three signaling
  options. Returns a map of `kind => [algorithm_int]` for every
  one that's present (empty map when none).

  ### Arguments

  * `options` — the `[{code, binary}]` list from the OPT
    record's `:options` field.

  ### Returns

  * `%{dau: [...], dhu: [...], n3u: [...]}` — only the keys
    actually present.

  ### Examples

      iex> ExDns.EDNSAlgorithmSignaling.find_in_options([])
      %{}

  """
  @spec find_in_options([{non_neg_integer(), binary()}]) :: map()
  def find_in_options(options) when is_list(options) do
    Enum.reduce(options, %{}, fn
      {@dau, payload}, acc -> Map.put(acc, :dau, decode_payload(payload))
      {@dhu, payload}, acc -> Map.put(acc, :dhu, decode_payload(payload))
      {@n3u, payload}, acc -> Map.put(acc, :n3u, decode_payload(payload))
      _, acc -> acc
    end)
  end

  @doc """
  What ExDns supports for each of the three signaling
  categories. Used to build outbound DAU/DHU/N3U options when
  iterating in recursor mode.

  ### Arguments

  * `kind` — `:dau`, `:dhu`, or `:n3u`.

  ### Returns

  * Sorted list of algorithm numbers.

  ### Examples

      iex> alg = ExDns.EDNSAlgorithmSignaling.supported(:dau)
      iex> 13 in alg
      true

  """
  @spec supported(:dau | :dhu | :n3u) :: [non_neg_integer()]
  def supported(:dau) do
    # Algorithms our validator can verify (RFC 8624-allowed
    # only — i.e. not the MUST-NOT-validate algorithms).
    [5, 7, 8, 10, 13, 14, 15, 16]
    |> Enum.filter(&ExDns.DNSSEC.AlgorithmPolicy.validation_allowed?/1)
  end

  def supported(:dhu) do
    # DS digest algorithms our `Rollover.compute_ds_digest/3`
    # implements: SHA-1 (1) and SHA-256 (2).
    [1, 2]
  end

  def supported(:n3u) do
    # The only RFC 5155 hash.
    [1]
  end
end
