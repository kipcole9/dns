defmodule ExDns.Zone.Additionals do
  @moduledoc """
  Auto-derive A/AAAA glue records for the additional section of
  a response, matching the BIND default of including target
  addresses for any NS, MX, or SRV record present in the
  answer or authority sections.

  ## Why

  Operators expect that adding `IN MX 10 mail.example.com` is
  enough — they should not have to also remember to publish
  `mail.example.com IN A …` glue separately. BIND, Knot DNS,
  PowerDNS, and the IANA root all auto-derive these. Without
  this, clients receive an MX/SRV/NS answer and immediately
  have to make a follow-up query for the target's address,
  doubling the round-trip count.

  ## Scope

  This module derives addresses we have *in storage* — it does
  not chase recursively. Out-of-bailiwick targets simply produce
  no additional record (the same as BIND).

  Records that already appear in the response (as an answer or
  in the supplied additional list) are not duplicated.

  ## Telemetry

  None — this is a hot-path helper. Counts surface through the
  existing per-response telemetry instead.
  """

  alias ExDns.Resource.{A, AAAA, MX, NS, SRV}
  alias ExDns.Storage

  @doc """
  Return the auto-derived A/AAAA glue records for `records`,
  excluding anything in `already_present` (answer + supplied
  additional).

  ### Arguments

  * `records` is the list of answer + authority records the
    response will carry.
  * `already_present` is a list of records already in the
    response (typically answer + supplied additional). Used to
    deduplicate.

  ### Returns

  * A list of `%A{}` and `%AAAA{}` records to append to the
    additional section. Empty when nothing matches.

  ### Examples

      iex> ExDns.Zone.Additionals.derive([], [])
      []

  """
  @spec derive([struct()], [struct()]) :: [struct()]
  def derive(records, already_present \\ [])
      when is_list(records) and is_list(already_present) do
    targets = collect_targets(records)
    skip = name_type_pairs(records ++ already_present)

    Enum.flat_map(targets, fn target ->
      lookup_addresses(target, skip)
    end)
    |> Enum.uniq()
  end

  defp collect_targets(records) do
    records
    |> Enum.flat_map(fn
      %NS{server: target} -> [target]
      %MX{server: target} -> [target]
      %SRV{target: target} -> [target]
      _ -> []
    end)
    |> Enum.map(&normalize/1)
    |> Enum.uniq()
    |> Enum.reject(&(&1 == ""))
  end

  defp lookup_addresses(target, skip) do
    a_records =
      case Storage.lookup(target, :a) do
        {:ok, _apex, records} -> Enum.reject(records, &skip?(&1, skip))
        _ -> []
      end

    aaaa_records =
      case Storage.lookup(target, :aaaa) do
        {:ok, _apex, records} -> Enum.reject(records, &skip?(&1, skip))
        _ -> []
      end

    a_records ++ aaaa_records
  end

  defp skip?(%A{name: name}, skip), do: MapSet.member?(skip, {normalize(name), :a})
  defp skip?(%AAAA{name: name}, skip), do: MapSet.member?(skip, {normalize(name), :aaaa})
  defp skip?(_, _), do: false

  defp name_type_pairs(records) do
    records
    |> Enum.flat_map(fn
      %A{name: name} -> [{normalize(name), :a}]
      %AAAA{name: name} -> [{normalize(name), :aaaa}]
      _ -> []
    end)
    |> MapSet.new()
  end

  defp normalize(nil), do: ""
  defp normalize(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end
end
