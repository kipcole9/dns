defmodule ExDns.DNSSEC.NSEC do
  @moduledoc """
  NSEC chain generation (RFC 4034 §4) for authenticating negative
  responses (NXDOMAIN, NODATA).

  Given the records in a zone, this module produces the NSEC RRset:
  one NSEC record per distinct owner name, ordered canonically, with
  each NSEC pointing at the next owner in the chain. The last NSEC
  wraps back to the apex.

  ## Type bitmap

  Each NSEC record carries a "type bit map" naming the resource types
  present at that owner. Encoded as a sequence of windows:

      <<window::8, length::8, bitmap::binary-size(length)>> …

  Where `window` is the high byte of the type code, and the bitmap's
  bit `n` (MSB-first) is set when the type with low byte `n` exists.

  We always include `NSEC` (47) and `RRSIG` (46) in the bitmap, since
  they're added by the signer.

  ## Canonical owner ordering

  RFC 4034 §6.1: names are compared by reversing the label list and
  sorting right-to-left (TLD-first). For example,

      a.example.com
      b.example.com
      example.com
      foo.bar.example.com

  sorts in a canonical chain.

  """

  alias ExDns.Resource.NSEC, as: NSECRR

  @doc """
  Returns the NSEC chain for `apex` covering every owner name that
  appears in `records`.

  ### Arguments

  * `apex` — the zone's apex name (e.g. `"example.com"`).
  * `records` — the zone's resource records (any list — names that
    don't fall under `apex` are ignored).
  * `options`:
    * `:ttl` — TTL to put on each NSEC record (default 3600).
    * `:extra_types` — list of type atoms to ALSO mark present on
      every NSEC bitmap regardless of whether the owner has them.
      Useful when the zone is signed: pass `[:rrsig, :nsec]` (which
      is the default).

  ### Returns

  * A list of `%ExDns.Resource.NSEC{}` records, sorted canonically.

  """
  @spec generate(binary(), [struct()], keyword()) :: [NSECRR.t()]
  def generate(apex, records, options \\ []) when is_binary(apex) and is_list(records) do
    ttl = Keyword.get(options, :ttl, 3600)
    extra_types = Keyword.get(options, :extra_types, [:rrsig, :nsec])
    extra_type_ints = Enum.map(extra_types, &ExDns.Resource.type_from/1)

    # Group records by canonical (lowercased, no trailing dot) owner.
    by_owner =
      records
      |> Enum.filter(&in_zone?(&1.name, apex))
      |> Enum.group_by(&normalize(&1.name))

    sorted_owners = by_owner |> Map.keys() |> sort_canonically()

    case sorted_owners do
      [] ->
        []

      _ ->
        chain_pairs = chain_pairs(sorted_owners, normalize(apex))

        for {owner, next_owner} <- chain_pairs do
          types =
            by_owner
            |> Map.fetch!(owner)
            |> Enum.map(&type_int_for/1)
            |> Kernel.++(extra_type_ints)
            |> Enum.uniq()

          %NSECRR{
            name: owner,
            ttl: ttl,
            class: :in,
            next_domain: next_owner,
            type_bit_maps: encode_type_bitmap(types)
          }
        end
    end
  end

  @doc """
  Returns the NSEC record from `chain` whose owner == `qname` — the
  record proving "this name exists but type X does not" for NODATA
  responses.
  """
  @spec for_owner([NSECRR.t()], binary()) :: NSECRR.t() | nil
  def for_owner(chain, qname) when is_list(chain) and is_binary(qname) do
    qname_norm = normalize(qname)
    Enum.find(chain, fn nsec -> normalize(nsec.name) == qname_norm end)
  end

  @doc """
  Returns the NSEC record from `chain` that "covers" `qname` — i.e.
  whose owner sorts before `qname` and whose `next_domain` sorts at
  or after `qname`. Used to prove NXDOMAIN.
  """
  @spec covering([NSECRR.t()], binary()) :: NSECRR.t() | nil
  def covering(chain, qname) when is_list(chain) and is_binary(qname) do
    qname_key = canonical_sort_key(normalize(qname))

    Enum.find(chain, fn nsec ->
      owner_key = canonical_sort_key(normalize(nsec.name))
      next_key = canonical_sort_key(normalize(nsec.next_domain))

      cond do
        # The queried name IS the NSEC's owner — that's NODATA territory,
        # not NXDOMAIN, so this NSEC doesn't "cover" the name in the
        # absence sense.
        compare(owner_key, qname_key) == :eq ->
          false

        # Single-owner zone (owner wraps to itself): every other name
        # is covered by definition.
        compare(owner_key, next_key) == :eq ->
          true

        # Normal case: owner < qname < next
        compare(owner_key, qname_key) == :lt and compare(qname_key, next_key) == :lt ->
          true

        # Wraparound (owner > next): qname is either > owner or < next
        compare(owner_key, next_key) == :gt and
            (compare(owner_key, qname_key) == :lt or compare(qname_key, next_key) == :lt) ->
          true

        true ->
          false
      end
    end)
  end

  # ----- helpers ------------------------------------------------------

  @doc false
  def encode_type_bitmap(type_ints) when is_list(type_ints) do
    type_ints
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.group_by(fn t -> div(t, 256) end)
    |> Enum.sort()
    |> Enum.map(&encode_window/1)
    |> IO.iodata_to_binary()
  end

  defp encode_window({window_block, type_ints}) do
    low_bytes = Enum.map(type_ints, fn t -> rem(t, 256) end)
    bitmap_length = div(Enum.max(low_bytes), 8) + 1
    bitmap_bits = List.duplicate(0, bitmap_length * 8)

    bits =
      Enum.reduce(low_bytes, bitmap_bits, fn b, acc ->
        List.replace_at(acc, b, 1)
      end)

    bitmap = bits_to_binary(bits)
    <<window_block::size(8), bitmap_length::size(8), bitmap::binary>>
  end

  defp bits_to_binary(bits) do
    bits
    |> Enum.chunk_every(8)
    |> Enum.map(fn byte_bits ->
      Enum.reduce(byte_bits, 0, fn bit, acc -> Bitwise.bor(Bitwise.bsl(acc, 1), bit) end)
    end)
    |> :erlang.list_to_binary()
  end

  defp type_int_for(record) do
    type_atom =
      record.__struct__
      |> Module.split()
      |> List.last()
      |> String.downcase()
      |> String.to_existing_atom()

    ExDns.Resource.type_from(type_atom)
  end

  defp in_zone?(name, apex) do
    name = normalize(name)
    apex = normalize(apex)
    name == apex or String.ends_with?(name, "." <> apex)
  end

  defp normalize(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end

  defp chain_pairs([only], apex), do: [{only, apex}]

  defp chain_pairs(sorted, apex) do
    pairs =
      sorted
      |> Enum.zip(tl(sorted))

    last_owner = List.last(sorted)
    pairs ++ [{last_owner, apex}]
  end

  # ----- canonical ordering (RFC 4034 §6.1) --------------------------

  @doc false
  def sort_canonically(names) when is_list(names) do
    Enum.sort_by(names, &canonical_sort_key/1)
  end

  defp canonical_sort_key(name) do
    name
    |> normalize()
    |> String.split(".", trim: true)
    |> Enum.reverse()
  end

  defp compare(a, a), do: :eq
  defp compare(a, b) when a < b, do: :lt
  defp compare(_a, _b), do: :gt
end
