defmodule ExDns.DNSSEC.DenialOfExistence do
  @moduledoc """
  Per-zone selection between NSEC and NSEC3 chains for proving
  denial of existence (NXDOMAIN, NODATA) on authoritative
  responses.

  Zones default to NSEC. Operators that prefer NSEC3 (zone
  enumeration resistance, opt-out for delegation-heavy TLDs)
  enable it per zone:

      config :ex_dns, :dnssec_zones, %{
        "example.test" => [denial: :nsec3, salt: <<0xAB, 0xCD>>,
                           iterations: 0, opt_out: false]
      }

  ## Returned shape

  * `authority_for/3` returns a list of records ready to drop
    into the response's authority section. The caller wraps
    this with the SOA + signs both as part of the usual
    response-building pipeline.

  ## RFC pointers

  * RFC 4034 §4 — NSEC.
  * RFC 5155 §7.2 — NSEC3 NODATA + NXDOMAIN proofs.
  * RFC 9276 — current operational guidance (NSEC3 iterations
    SHOULD be 0; salt SHOULD be empty).
  """

  alias ExDns.DNSSEC.{NSEC, NSEC3}
  alias ExDns.DNSSEC.NSEC3.{Chain, Proof}
  alias ExDns.Storage

  @type kind :: :nodata | :nxdomain

  @doc """
  Return the NSEC or NSEC3 records that prove `kind` for
  `qname` in zone `apex`.

  ### Arguments

  * `apex` — the (lower-case, dot-trimmed) zone apex.
  * `qname` — the queried name.
  * `kind` — `:nodata` or `:nxdomain`.

  ### Returns

  * A (possibly empty) list of `%ExDns.Resource.NSEC{}` or
    `%ExDns.Resource.NSEC3{}` records.

  ### Examples

      iex> ExDns.DNSSEC.DenialOfExistence.authority_for("nope.test",
      ...>   "anything.nope.test", :nxdomain)
      []

  """
  @spec authority_for(binary(), binary(), kind()) :: [struct()]
  def authority_for(apex, qname, kind) when kind in [:nodata, :nxdomain] do
    case Storage.dump_zone(apex) do
      {:ok, records} ->
        case denial_mode(apex) do
          :nsec3 -> nsec3_proof(apex, records, qname, kind)
          _ -> nsec_proof(apex, records, qname, kind)
        end

      _ ->
        []
    end
  end

  @doc """
  Returns the configured denial mode for `apex` — `:nsec`
  (default) or `:nsec3`.

  ### Examples

      iex> Application.delete_env(:ex_dns, :dnssec_zones)
      iex> ExDns.DNSSEC.DenialOfExistence.denial_mode("any.zone")
      :nsec

  """
  @spec denial_mode(binary()) :: :nsec | :nsec3
  def denial_mode(apex) when is_binary(apex) do
    apex
    |> per_zone_options()
    |> Keyword.get(:denial, :nsec)
  end

  @doc """
  Returns the per-zone DNSSEC options keyword list for `apex`,
  or an empty list when the zone is not configured.
  """
  @spec per_zone_options(binary()) :: keyword()
  def per_zone_options(apex) do
    apex_norm = apex |> String.trim_trailing(".") |> String.downcase(:ascii)

    case Application.get_env(:ex_dns, :dnssec_zones, %{}) do
      map when is_map(map) ->
        case Enum.find(map, fn {k, _} -> normalize_key(k) == apex_norm end) do
          nil -> []
          {_, options} -> normalise_options(options)
        end

      list when is_list(list) ->
        case Enum.find(list, fn {k, _} -> normalize_key(k) == apex_norm end) do
          nil -> []
          {_, options} -> normalise_options(options)
        end

      _ ->
        []
    end
  end

  defp normalize_key(name) when is_atom(name), do: name |> Atom.to_string() |> normalize_key()
  defp normalize_key(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end

  defp normalise_options(options) when is_list(options), do: options
  defp normalise_options(options) when is_map(options), do: Enum.into(options, [])

  # ----- NSEC ----------------------------------------------------------

  defp nsec_proof(apex, records, qname, :nodata) do
    chain = NSEC.generate(apex, records)

    case NSEC.for_owner(chain, qname) do
      nil -> []
      record -> [record]
    end
  end

  defp nsec_proof(apex, records, qname, :nxdomain) do
    chain = NSEC.generate(apex, records)

    case NSEC.covering(chain, qname) do
      nil -> []
      record -> [record]
    end
  end

  # ----- NSEC3 ---------------------------------------------------------

  defp nsec3_proof(apex, records, qname, kind) do
    options = per_zone_options(apex)

    chain_options = [
      salt: Keyword.get(options, :salt, <<>>),
      iterations: Keyword.get(options, :iterations, 0),
      opt_out: Keyword.get(options, :opt_out, false)
    ]

    case build_nsec3_chain(apex, records, chain_options) do
      [] ->
        []

      chain ->
        case kind do
          :nodata -> Proof.nodata(chain, qname)
          :nxdomain -> Proof.nxdomain(chain, qname)
        end
    end
  end

  defp build_nsec3_chain(apex, records, chain_options) do
    names_to_types = collect_names_with_types(apex, records)

    if map_size(names_to_types) == 0 do
      []
    else
      Chain.build(apex, names_to_types, chain_options)
    end
  end

  defp collect_names_with_types(apex, records) do
    apex_norm = canonical(apex)

    records
    |> Enum.reduce(%{}, fn record, acc ->
      case record_name_and_type(record) do
        {name, type} ->
          name = canonical(name)

          if String.ends_with?(name, apex_norm) or name == apex_norm do
            Map.update(acc, name, [type], fn types -> Enum.uniq([type | types]) end)
          else
            acc
          end

        :ignore ->
          acc
      end
    end)
  end

  defp record_name_and_type(%{name: name, __struct__: struct})
       when is_binary(name) do
    {name, struct_to_qtype(struct)}
  end

  defp record_name_and_type(_), do: :ignore

  defp struct_to_qtype(struct) do
    struct
    |> Module.split()
    |> List.last()
    |> String.downcase()
    |> String.to_atom()
  end

  defp canonical(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end

  # NSEC3 module is referenced for chain — silence unused warning
  # if compile order is unusual.
  _ = NSEC3
end
