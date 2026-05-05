defmodule ExDns.Zone.Validate do
  @moduledoc """
  Pre-flight zone-content validation, run by the loader to
  catch operator typos before the wire ever sees them.

  Without this, a CNAME-coexistence violation, a missing glue
  record, or a non-monotonic SOA bump rolls out silently and
  surfaces as bizarre client behaviour later. The validator
  surfaces every issue up-front in one call.

  ## Checks

  | Check | Why it matters |
  |---|---|
  | **SOA presence** | RFC 1035 §6.1.2: every zone has exactly one SOA at the apex. |
  | **Class consistency** | Every record in a zone shares one class (RFC 1035). |
  | **CNAME coexistence** | RFC 1034 §3.6.2: a name with a CNAME cannot carry any other RRset. Common typo from `zone-edit` workflows. |
  | **Glue presence** | RFC 1912 §2.5: when a zone delegates `sub.example.com` to `ns.sub.example.com` (in-bailiwick), the parent zone MUST include glue A/AAAA so resolvers can reach the nameserver. |
  | **SOA serial monotonicity** | RFC 1982-aware comparison: when re-loading, the new serial must be "later" than the previously-stored one. |

  Each check returns either `:ok` or `{:error, [reason]}` and
  `validate/3` aggregates them so a single call surfaces every
  problem the operator needs to fix.

  ## Severity

  All checks are presented as errors. A future enhancement
  could split them into `:error` (refuse to load) and
  `:warning` (load but warn) — for now the loader treats every
  validation failure as fatal.
  """

  alias ExDns.Resource.{A, AAAA, CNAME, NS, SOA}

  @typedoc "A single validation problem."
  @type problem ::
          {:no_soa, binary()}
          | {:multiple_soas, binary()}
          | {:soa_not_at_apex, binary()}
          | {:soa_serial_did_not_advance, binary(), integer(), integer()}
          | {:class_mismatch, [atom()]}
          | {:cname_coexistence, binary()}
          | {:missing_glue, binary(), binary()}

  @doc """
  Validate a zone's record list against the canonical
  expectations.

  ### Arguments

  * `apex` — the zone apex.
  * `records` — the new record list (typically just-parsed
    from a zone file).
  * `options` — keyword list:

  ### Options

  * `:previous_records` — the previously-stored record list
    for the same apex. When provided, enables the SOA-serial
    monotonicity check. Default `nil` (skip the check).

  ### Returns

  * `:ok` when every check passes.
  * `{:error, [problem]}` listing every failure encountered.

  ### Examples

      iex> ExDns.Zone.Validate.validate("example.test", [])
      {:error, [{:no_soa, "example.test"}]}

  """
  @spec validate(binary(), [struct()], keyword()) :: :ok | {:error, [problem()]}
  def validate(apex, records, options \\ []) when is_binary(apex) and is_list(records) do
    apex_norm = canonical(apex)

    problems =
      List.flatten([
        check_soa(records, apex_norm),
        check_class_consistency(records),
        check_cname_coexistence(records),
        check_glue(records, apex_norm),
        check_serial_monotonicity(records, Keyword.get(options, :previous_records), apex_norm)
      ])

    case problems do
      [] -> :ok
      _ -> {:error, problems}
    end
  end

  # ----- SOA --------------------------------------------------------

  defp check_soa(records, apex) do
    soas = Enum.filter(records, &match?(%SOA{}, &1))

    cond do
      soas == [] -> [{:no_soa, apex}]
      length(soas) > 1 -> [{:multiple_soas, apex}]
      canonical(hd(soas).name) != apex -> [{:soa_not_at_apex, canonical(hd(soas).name)}]
      true -> []
    end
  end

  # ----- class consistency -----------------------------------------

  defp check_class_consistency(records) do
    classes = records |> Enum.map(& &1.class) |> Enum.uniq()

    case classes do
      [] -> []
      [_one] -> []
      mixed -> [{:class_mismatch, mixed}]
    end
  end

  # ----- CNAME coexistence -----------------------------------------

  defp check_cname_coexistence(records) do
    cname_owners = for %CNAME{name: n} <- records, do: canonical(n)

    other_owners =
      for record <- records,
          not match?(%CNAME{}, record),
          do: canonical(record.name)

    cname_set = MapSet.new(cname_owners)
    other_set = MapSet.new(other_owners)

    MapSet.intersection(cname_set, other_set)
    |> Enum.map(fn name -> {:cname_coexistence, name} end)
  end

  # ----- glue presence ---------------------------------------------

  # For each delegation NS that points to an in-bailiwick name
  # (a name within or below `apex`), the zone MUST include glue
  # A or AAAA for that nameserver. RFC 1912 §2.5.
  defp check_glue(records, apex) do
    delegations =
      for %NS{name: owner, server: target} <- records,
          canonical(owner) != apex,
          in_bailiwick?(target, apex),
          do: {canonical(owner), canonical(target)}

    glued =
      for record <- records,
          match?(%A{}, record) or match?(%AAAA{}, record),
          do: canonical(record.name),
          into: MapSet.new()

    for {delegation, target} <- delegations,
        not MapSet.member?(glued, target),
        do: {:missing_glue, delegation, target}
  end

  defp in_bailiwick?(target, apex) do
    target_norm = canonical(target)
    target_norm == apex or String.ends_with?(target_norm, "." <> apex)
  end

  # ----- SOA serial monotonicity -----------------------------------

  defp check_serial_monotonicity(_records, nil, _apex), do: []

  defp check_serial_monotonicity(records, previous, apex) do
    new_serial = serial_of(records, apex)
    old_serial = serial_of(previous, apex)

    cond do
      new_serial == nil or old_serial == nil ->
        []

      new_serial == old_serial ->
        # RFC 1982 says equal is "neither greater nor less". For
        # zone-reload purposes equal-serial-with-changed-data is
        # the typo we want to catch — flag it.
        [{:soa_serial_did_not_advance, apex, old_serial, new_serial}]

      not serial_advanced?(old_serial, new_serial) ->
        [{:soa_serial_did_not_advance, apex, old_serial, new_serial}]

      true ->
        []
    end
  end

  defp serial_of(records, apex) do
    case Enum.find(records, fn r -> match?(%SOA{}, r) and canonical(r.name) == apex end) do
      %SOA{serial: serial} when is_integer(serial) -> serial
      _ -> nil
    end
  end

  defp serial_advanced?(old, new) when is_integer(old) and is_integer(new) do
    diff = rem(new - old + 0x100000000, 0x100000000)
    diff > 0 and diff < 0x80000000
  end

  defp canonical(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end
end
