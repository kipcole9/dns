defmodule ExDns.DNSSEC.NSEC3.Chain do
  @moduledoc """
  Construct the NSEC3 chain for an authoritative zone.

  Given the names that exist in the zone (and the types present
  at each), this module produces a list of `%ExDns.Resource.NSEC3{}`
  records that form a complete chain per RFC 5155 §7:

  1. Hash every name with SHA-1 + the zone's salt + iterations.
  2. Sort the hashes in canonical base32hex order.
  3. For each entry `i`, `next_hashed_owner` = hash of entry
     `i+1` (with wrap-around: the last entry points at the
     first).
  4. The owner name of each NSEC3 is `<base32hex(hash)>.<zone>`.
  5. The type bitmap at each owner enumerates the types present
     at the *original* (un-hashed) name plus `RRSIG` and `NSEC3`
     itself.

  ## Public API

  * `build/3` — given the zone apex, a `name => [qtype]` map,
    and chain options, return the list of `%NSEC3{}` records.
  """

  alias ExDns.DNSSEC.NSEC3
  alias ExDns.Resource.NSEC3, as: NSEC3Record

  @default_ttl 3600

  @doc """
  Build the NSEC3 chain for `zone`.

  ### Arguments

  * `zone` is the apex (binary).

  * `names_to_types` is a map `%{name => [qtype_atom]}` listing
    every existing name in the zone and the qtypes present at
    that name. The apex itself MUST appear in this map.

  * `options` is a keyword list:

  ### Options

  * `:salt` — defaults to `<<>>`.
  * `:iterations` — defaults to `0` (per RFC 9276).
  * `:ttl` — TTL on each NSEC3 record. Defaults to `3600`.
  * `:flags` — NSEC3 flags byte. Defaults to `0`. (`1` = opt-out.)

  ### Returns

  * `[%ExDns.Resource.NSEC3{}, ...]` — the chain, sorted by
    hashed owner name.

  ### Examples

      iex> chain = ExDns.DNSSEC.NSEC3.Chain.build("example.test", %{
      ...>   "example.test" => [:soa, :ns],
      ...>   "host.example.test" => [:a]
      ...> })
      iex> length(chain)
      2

  """
  @spec build(binary(), %{binary() => [atom()]}, keyword()) :: [NSEC3Record.t()]
  def build(zone, names_to_types, options \\ [])
      when is_binary(zone) and is_map(names_to_types) do
    salt = Keyword.get(options, :salt, <<>>)
    iterations = Keyword.get(options, :iterations, 0)
    ttl = Keyword.get(options, :ttl, @default_ttl)
    opt_out? = Keyword.get(options, :opt_out, false)
    flags = compute_flags(opt_out?, Keyword.get(options, :flags, 0))

    zone_norm = canonical(zone)

    # When opt-out is on, RFC 5155 §6 says insecure delegations
    # (names that have NS but no DS, and aren't the apex) are
    # NOT represented in the NSEC3 chain. Filter them out before
    # hashing so the chain skips over them entirely.
    names_to_types =
      if opt_out? do
        names_to_types
        |> Enum.reject(fn {name, types} ->
          insecure_delegation?(name, types, zone_norm)
        end)
        |> Map.new()
      else
        names_to_types
      end

    # Hash every name once; produce {hash, name, types}.
    hashed =
      names_to_types
      |> Enum.map(fn {name, types} ->
        {NSEC3.hash_name(name, salt, iterations), name, types}
      end)
      |> Enum.sort_by(fn {hash, _, _} -> hash end)

    # The chain wraps: the last record's next_hashed_owner is the
    # first hash. Achieved by zipping hashed against its rotation.
    rotated = rotate_left(hashed)

    Enum.zip(hashed, rotated)
    |> Enum.map(fn {{hash, _name, types}, {next_hash, _, _}} ->
      types_with_rrsig_and_nsec3 = Enum.uniq(types ++ [:rrsig, :nsec3])

      %NSEC3Record{
        name: NSEC3.hashed_owner_from_hash(hash, zone),
        ttl: ttl,
        class: :in,
        hash_algorithm: NSEC3.hash_algorithm(),
        flags: flags,
        iterations: iterations,
        salt: salt,
        next_hashed_owner: next_hash,
        type_bit_maps: encode_type_bitmap(types_with_rrsig_and_nsec3)
      }
    end)
  end

  @doc """
  Encode a list of qtype atoms as the type-bit-map byte sequence
  shared by NSEC and NSEC3 (RFC 4034 §4.1.2).

  Exposed as a helper so other DNSSEC code can build bitmaps
  without going through the chain constructor.

  ### Arguments

  * `qtypes` — list of qtype atoms (e.g. `[:a, :ns, :rrsig]`).

  ### Returns

  * The encoded bitmap binary.

  ### Examples

      iex> bytes = ExDns.DNSSEC.NSEC3.Chain.encode_type_bitmap([:a])
      iex> byte_size(bytes) > 0
      true

  """
  @spec encode_type_bitmap([atom()]) :: binary()
  def encode_type_bitmap(qtypes) when is_list(qtypes) do
    qtypes
    |> Enum.flat_map(&safe_type_from/1)
    |> Enum.group_by(&div(&1, 256))
    |> Enum.sort_by(fn {window, _} -> window end)
    |> Enum.map(fn {window, types} ->
      max_offset = types |> Enum.map(&rem(&1, 256)) |> Enum.max()
      bytes_needed = div(max_offset, 8) + 1
      bits = build_window_bits(types, bytes_needed)

      <<window::size(8), bytes_needed::size(8), bits::binary>>
    end)
    |> IO.iodata_to_binary()
  end

  # `ExDns.Resource.type_from/1` raises FunctionClauseError for
  # qtype atoms it doesn't know about. Treat unknown atoms as
  # absent (return an empty list so flat_map drops them).
  defp safe_type_from(qtype) do
    [ExDns.Resource.type_from(qtype)]
  rescue
    FunctionClauseError -> []
  end

  defp build_window_bits(types, bytes_needed) do
    import Bitwise
    empty = :binary.copy(<<0>>, bytes_needed)

    Enum.reduce(types, empty, fn type_int, acc ->
      offset = rem(type_int, 256)
      byte_idx = div(offset, 8)
      bit_idx = 7 - rem(offset, 8)
      <<head::binary-size(^byte_idx), b::8, tail::binary>> = acc
      <<head::binary, b ||| bsl(1, bit_idx)::8, tail::binary>>
    end)
  end

  defp rotate_left([]), do: []
  defp rotate_left([h | t]), do: t ++ [h]

  # RFC 5155 §3.1.2: opt-out flag is bit 0 of the flags byte.
  # Honour an explicit operator-supplied :flags value but force
  # the bit on when :opt_out is true so the two options compose.
  defp compute_flags(true, base_flags), do: Bitwise.bor(base_flags, 1)
  defp compute_flags(false, base_flags), do: base_flags

  # Insecure delegation = name has NS records but no DS records,
  # and isn't the zone apex (the apex's NS+SOA pair is always
  # represented). RFC 5155 §6.
  defp insecure_delegation?(name, types, zone_norm) do
    name_norm = canonical(name)

    name_norm != zone_norm and
      :ns in types and
      :ds not in types
  end

  defp canonical(name) when is_binary(name) do
    name |> String.downcase(:ascii) |> String.trim_trailing(".")
  end
end
