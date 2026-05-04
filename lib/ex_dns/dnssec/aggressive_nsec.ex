defmodule ExDns.DNSSEC.AggressiveNSEC do
  @moduledoc """
  Aggressive use of cached NSEC/NSEC3 records (RFC 8198).

  Every NSEC record proves a *range*: "between owner name `O` and
  `next_domain N`, no other names exist". A recursor that has
  cached such an NSEC can answer NXDOMAIN for any qname in `(O,
  N)` without hitting the upstream — every hit reduces both
  latency and load on the parent zone.

  Likewise, the NSEC at owner `O` lists exactly which RRtypes exist
  at `O`, so a query for `O` of any type *not* in that bitmap can
  be answered NODATA from the cache.

  ## Predicates

  * `proves_nxdomain?/2` — given a qname and a list of cached NSEC
    records, returns the NSEC that proves NXDOMAIN, if any.

  * `proves_nodata?/3` — given qname + qtype + NSECs, returns the
    NSEC that proves NODATA at that qname for that qtype.

  ## Canonical name comparison

  Names are compared per RFC 4034 §6.1: case-folded, label-by-label
  from the rightmost label, with shorter (more-specific) names
  sorting before longer ones at any prefix tie.
  """

  alias ExDns.Resource.NSEC

  @doc """
  Does any NSEC in `nsec_records` prove that `qname` does not
  exist?

  ### Arguments

  * `qname` is the name being queried (binary).
  * `nsec_records` is the list of currently-cached NSEC records.

  ### Returns

  * `{:yes, nsec}` — the NSEC whose interval covers `qname`.
  * `:no` — nothing in the list proves NXDOMAIN.

  ### Examples

      iex> ExDns.DNSSEC.AggressiveNSEC.proves_nxdomain?("missing.test", [])
      :no

  """
  @spec proves_nxdomain?(binary(), [NSEC.t()]) :: {:yes, NSEC.t()} | :no
  def proves_nxdomain?(qname, nsec_records) when is_binary(qname) and is_list(nsec_records) do
    target = canonical(qname)

    Enum.find(nsec_records, fn %NSEC{name: owner, next_domain: next} ->
      owner_c = canonical(owner)
      next_c = canonical(next)

      case canonical_compare(owner_c, target) do
        :lt -> covers_strict?(target, next_c, owner_c)
        _ -> false
      end
    end)
    |> case do
      nil -> :no
      nsec -> {:yes, nsec}
    end
  end

  @doc """
  Does the NSEC at `qname` prove that `qtype` does not exist
  there?

  ### Arguments

  * `qname` — the queried name.
  * `qtype` — the queried type atom.
  * `nsec_records` — list of cached NSEC records.

  ### Returns

  * `{:yes, nsec}` if some NSEC owns `qname` and its type bitmap
    does not include `qtype`.
  * `:no` otherwise.

  ### Examples

      iex> ExDns.DNSSEC.AggressiveNSEC.proves_nodata?("nothing.test", :a, [])
      :no

  """
  @spec proves_nodata?(binary(), atom(), [NSEC.t()]) :: {:yes, NSEC.t()} | :no
  def proves_nodata?(qname, qtype, nsec_records)
      when is_binary(qname) and is_atom(qtype) and is_list(nsec_records) do
    target = canonical(qname)

    Enum.find(nsec_records, fn %NSEC{name: owner} = nsec ->
      canonical(owner) == target and not type_in_bitmap?(qtype, nsec.type_bit_maps)
    end)
    |> case do
      nil -> :no
      nsec -> {:yes, nsec}
    end
  end

  # ----- canonical name comparison ----------------------------------

  @doc false
  def canonical(name) when is_binary(name) do
    name
    |> String.downcase(:ascii)
    |> String.trim_trailing(".")
  end

  @doc false
  # RFC 4034 §6.1: compare names label-by-label, rightmost first.
  # Inputs are case-folded and trailing-dot-stripped before
  # comparison so callers don't have to canonicalise first.
  # Returns :lt | :eq | :gt.
  def canonical_compare(a, b) when is_binary(a) and is_binary(b) do
    a_labels = a |> canonical() |> String.split(".", trim: true) |> Enum.reverse()
    b_labels = b |> canonical() |> String.split(".", trim: true) |> Enum.reverse()
    compare_labels(a_labels, b_labels)
  end

  defp compare_labels([], []), do: :eq
  defp compare_labels([], _), do: :lt
  defp compare_labels(_, []), do: :gt

  defp compare_labels([al | a_rest], [bl | b_rest]) do
    case bytewise_compare(al, bl) do
      :eq -> compare_labels(a_rest, b_rest)
      other -> other
    end
  end

  defp bytewise_compare(a, b) when a == b, do: :eq
  defp bytewise_compare(a, b) when a < b, do: :lt
  defp bytewise_compare(_, _), do: :gt

  # `target` falls strictly between owner and next when:
  #   owner < target < next  (normal case)
  #   target > owner and (next wraps around to before owner) (apex/wrap case)
  defp covers_strict?(target, next, owner) do
    owner_to_target = canonical_compare(owner, target)
    target_to_next = canonical_compare(target, next)
    next_to_owner = canonical_compare(next, owner)

    cond do
      # Normal interval (owner, next).
      owner_to_target == :lt and target_to_next == :lt ->
        true

      # Last NSEC in the zone — `next` wraps to the apex (sorts
      # before every other name in the zone). target > owner
      # suffices.
      next_to_owner != :gt and owner_to_target == :lt ->
        true

      true ->
        false
    end
  end

  # ----- type-bitmap parsing ---------------------------------------

  # NSEC type bitmaps (RFC 4034 §4.1.2) are a sequence of
  # window blocks: window-number (1B), bitmap-length (1B),
  # bitmap-bits (1..32 bytes). RRtype N has bit `N rem 256` in
  # window `div(N, 256)`.
  defp type_in_bitmap?(qtype, bitmap) when is_binary(bitmap) do
    case ExDns.Resource.type_from(qtype) do
      n when is_integer(n) -> bitmap_contains?(bitmap, n)
      _ -> false
    end
  end

  defp bitmap_contains?(<<>>, _), do: false

  defp bitmap_contains?(<<window::8, length::8, bits::binary-size(length), rest::binary>>, qtype_int) do
    target_window = div(qtype_int, 256)

    cond do
      window == target_window ->
        offset = rem(qtype_int, 256)
        byte_index = div(offset, 8)
        bit_index = 7 - rem(offset, 8)

        if byte_index < byte_size(bits) do
          <<_::binary-size(^byte_index), b::8, _::binary>> = bits
          import Bitwise
          (b &&& bsl(1, bit_index)) != 0
        else
          false
        end

      true ->
        bitmap_contains?(rest, qtype_int)
    end
  end

  defp bitmap_contains?(_, _), do: false
end
