defmodule ExDns.DNSSEC.NSEC3.Proof do
  @moduledoc """
  Pick the NSEC3 records that prove a NODATA or NXDOMAIN
  response, given the zone's full NSEC3 chain.

  ## NODATA proof (RFC 5155 §7.2.3)

  A single NSEC3 whose hashed owner matches the qname; the
  type bitmap MUST omit the queried qtype (and its CNAME, if
  applicable).

  ## NXDOMAIN proof (RFC 5155 §7.2.1 — closest-encloser proof)

  Three NSEC3 records:

  1. The NSEC3 that **matches** the closest encloser (the
     longest existing ancestor of qname).
  2. The NSEC3 that **covers** the next-closer name (the name
     formed by adding one label from qname back onto the closest
     encloser).
  3. The NSEC3 that **covers** the wildcard at the closest
     encloser (`*.<closest-encloser>`).

  If the same NSEC3 happens to satisfy more than one of those
  roles, it appears once — the response only needs the unique
  set.

  ## Wildcard NODATA proof (RFC 5155 §7.2.5)

  Two records: the NSEC3 matching the wildcard, plus the
  NSEC3 covering the next-closer name. Not yet supported here
  — falls back to the NXDOMAIN-style closest-encloser proof.
  """

  alias ExDns.DNSSEC.NSEC3
  alias ExDns.Resource.NSEC3, as: NSEC3Record

  @doc """
  Build the NODATA proof: the single NSEC3 record matching
  `qname`, or `[]` when no matching NSEC3 exists in the chain.

  ### Arguments

  * `chain` — the full NSEC3 chain for the zone.
  * `qname` — the queried name (binary).

  ### Returns

  * `[%NSEC3{}]` on a hit.
  * `[]` when no NSEC3 in the chain matches `qname`.
  """
  @spec nodata([NSEC3Record.t()], binary()) :: [NSEC3Record.t()]
  def nodata([], _qname), do: []

  def nodata([first | _] = chain, qname) when is_binary(qname) do
    zone = derive_zone(first)
    target_hash = hash(qname, first)

    case Enum.find(chain, fn r -> hashed_label(r.name, zone) == target_hash end) do
      nil -> []
      match -> [match]
    end
  end

  @doc """
  Build the closest-encloser NXDOMAIN proof for `qname`.

  ### Arguments

  * `chain` — the full NSEC3 chain for the zone.
  * `qname` — the queried name that does not exist.

  ### Returns

  * A list of 1 to 3 unique NSEC3 records — the closest-encloser
    match, the next-closer cover, and the wildcard cover. Empty
    list when the chain isn't a valid NSEC3 chain (e.g. empty).
  """
  @spec nxdomain([NSEC3Record.t()], binary()) :: [NSEC3Record.t()]
  def nxdomain([], _qname), do: []

  def nxdomain([first | _] = chain, qname) when is_binary(qname) do
    zone = derive_zone(first)
    qname_norm = canonical(qname)

    case find_closest_encloser(chain, qname_norm, zone) do
      nil ->
        []

      {closest_encloser, next_closer} ->
        match = find_match(chain, closest_encloser, zone)
        next_cover = find_covering(chain, next_closer, zone)
        wildcard_cover = find_covering(chain, "*." <> closest_encloser, zone)

        [match, next_cover, wildcard_cover]
        |> Enum.reject(&is_nil/1)
        |> Enum.uniq()
    end
  end

  # ----- closest encloser ----------------------------------------------

  defp find_closest_encloser(chain, qname, zone) do
    qname
    |> ancestor_chain(zone)
    |> Enum.reduce_while(nil, fn {ancestor, next_closer}, _ ->
      if find_match(chain, ancestor, zone) do
        {:halt, {ancestor, next_closer}}
      else
        {:cont, nil}
      end
    end)
  end

  # Build [{ancestor, next_closer_below_it}, ...] starting with
  # the parent and walking up to the apex.
  defp ancestor_chain(qname, zone) do
    qname
    |> labels_above(zone)
    |> Enum.zip(below_each(qname, zone))
  end

  # ["sub.host.example", "host.example", "example"] when given
  # qname="x.sub.host.example" and zone="example".
  defp labels_above(qname, zone) do
    qname
    |> String.split(".")
    |> Enum.with_index()
    |> Enum.flat_map(fn {_, idx} ->
      ancestor =
        qname
        |> String.split(".")
        |> Enum.drop(idx + 1)
        |> Enum.join(".")

      cond do
        ancestor == "" -> []
        ancestor == zone -> [zone]
        String.ends_with?(ancestor, "." <> zone) -> [ancestor]
        true -> []
      end
    end)
  end

  # For each ancestor, the corresponding "next closer" is one
  # label deeper toward the qname. Build by reusing labels_above
  # offset by one.
  defp below_each(qname, zone) do
    labels = String.split(qname, ".")

    Enum.map(0..(length(labels) - 1), fn idx ->
      labels |> Enum.drop(idx) |> Enum.join(".")
    end)
    |> Enum.filter(fn name ->
      name != "" and (name == zone or String.ends_with?(name, "." <> zone) or name == qname)
    end)
  end

  # ----- match / cover --------------------------------------------------

  defp find_match(chain, name, zone) do
    target_hash = hash(name, hd(chain))
    Enum.find(chain, fn r -> hashed_label(r.name, zone) == target_hash end)
  end

  defp find_covering(chain, name, zone) do
    target_hash = hash(name, hd(chain))

    Enum.find(chain, fn r ->
      owner_hash = hashed_label(r.name, zone)
      next_hash = base32hex_encode(r.next_hashed_owner)
      covers?(target_hash, owner_hash, next_hash)
    end)
  end

  # `target` strictly between `owner` (exclusive) and `next` (exclusive),
  # with wrap-around when next < owner (the chain is a ring).
  defp covers?(target, owner, next) do
    cond do
      owner < next -> owner < target and target < next
      owner > next -> target > owner or target < next
      true -> false
    end
  end

  # ----- helpers -------------------------------------------------------

  defp derive_zone(%NSEC3Record{name: owner_name}) do
    case String.split(owner_name, ".", parts: 2) do
      [_hashed, zone] -> canonical(zone)
      [_only] -> ""
    end
  end

  defp hash(name, %NSEC3Record{salt: salt, iterations: iterations}) do
    NSEC3.hash_name(name, salt, iterations)
  end

  defp hashed_label(owner_name, zone) do
    case String.split(owner_name, ".", parts: 2) do
      [label, ^zone] -> base32hex_decode(label)
      [label] when zone == "" -> base32hex_decode(label)
      _ -> <<>>
    end
  end

  defp base32hex_encode(bin) when is_binary(bin) do
    Base.hex_encode32(bin, padding: false, case: :lower)
  end

  defp base32hex_decode(label) when is_binary(label) do
    case Base.hex_decode32(String.upcase(label, :ascii), padding: false) do
      {:ok, bin} -> bin
      :error -> <<>>
    end
  end

  defp canonical(name) when is_binary(name) do
    name
    |> String.trim_trailing(".")
    |> String.downcase(:ascii)
  end
end
