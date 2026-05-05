defmodule ExDns.RPZ do
  @moduledoc """
  Response Policy Zones (RPZ) — the de-facto BIND-style
  format for expressing DNS-based blocklists, allow-lists,
  and walled-garden redirects.

  An RPZ is a regular DNS zone whose records encode policy
  rules:

  * The **owner name** (left-hand side) names the trigger —
    the qname (or response IP / nameserver / etc.) the rule
    matches.
  * The **record type + value** (right-hand side) names the
    action — return NXDOMAIN, NODATA, redirect, etc.

  This module parses an RPZ zone (the records list produced
  by `ExDns.Zone.load_file/1`) into a structured rule set
  ready to be consumed by a policy / plugin layer. The
  runtime application of the rules is intentionally out of
  scope here — the parser alone is what unblocks BIND
  operators with existing RPZ zone files from migrating.

  ## Triggers supported

  | Owner shape (relative to apex)            | Trigger meaning                         |
  |-------------------------------------------|-----------------------------------------|
  | `example.com`                             | qname == `example.com` (exact)          |
  | `*.example.com`                           | qname matches `*.example.com` (wildcard)|
  | `32.1.0.0.10.rpz-ip`                      | response IP == `10.0.0.1`               |
  | `48.zz.0.0.0.0.0.db8.2001.rpz-ip`         | response IP == `2001:db8::` (IPv6 /48)  |

  Other trigger labels (`rpz-nsdname`, `rpz-nsip`,
  `rpz-client-ip`) are parsed but emitted as `:other` for
  now — the policy layer can ignore or handle them as it
  sees fit.

  ## Actions supported (RFC 8499 / BIND RPZ syntax)

  | Right-hand side               | Action atom                |
  |-------------------------------|----------------------------|
  | `CNAME .`                     | `:nxdomain`                |
  | `CNAME *.`                    | `:nodata`                  |
  | `CNAME rpz-passthru.`         | `:passthru`                |
  | `CNAME rpz-drop.`             | `:drop`                    |
  | `CNAME rpz-tcp-only.`         | `:tcp_only`                |
  | `CNAME other.target.`         | `{:redirect, "other.target"}` |
  | `A <addr>` / `AAAA <addr>`    | `{:synthesise, [records]}` |
  | anything else                 | `{:synthesise, [records]}` |
  """

  alias ExDns.Resource.{A, AAAA, CNAME, SOA}

  defmodule Rule do
    @moduledoc "One parsed RPZ rule: a `{trigger, action}` pair."
    defstruct [:trigger, :action, :ttl]

    @type t :: %__MODULE__{
            trigger:
              {:qname, binary()}
              | {:wildcard, binary()}
              | {:rpz_ip, :inet.ip_address(), 0..128}
              | {:other, binary()},
            action:
              :nxdomain
              | :nodata
              | :passthru
              | :drop
              | :tcp_only
              | {:redirect, binary()}
              | {:synthesise, [struct()]},
            ttl: non_neg_integer()
          }
  end

  @doc """
  Parse the records of an RPZ zone into a list of `Rule`
  structs.

  ### Arguments

  * `apex` — the RPZ zone's apex (binary).
  * `records` — every record in the RPZ zone (typically the
    output of `ExDns.Zone.load_file/1`).

  ### Returns

  * A list of `%Rule{}` ordered as the records appear in the
    input. The SOA + apex NS records are filtered out — they
    aren't policy rules.

  ### Examples

      iex> ExDns.RPZ.parse("rpz.example", [])
      []

  """
  @spec parse(binary(), [struct()]) :: [Rule.t()]
  def parse(apex, records) when is_binary(apex) and is_list(records) do
    apex_norm = canonical(apex)

    records
    |> Enum.reject(fn r -> apex_owned_meta?(r, apex_norm) end)
    |> Enum.flat_map(&record_to_rule(&1, apex_norm))
    |> consolidate_synthesised()
  end

  # ----- record → rule ---------------------------------------------

  defp record_to_rule(record, apex_norm) do
    case classify_trigger(record.name, apex_norm) do
      :ignore -> []
      trigger -> [%Rule{trigger: trigger, action: classify_action(record), ttl: record.ttl}]
    end
  end

  # SOA + apex-owned NS: zone metadata, never policy rules.
  defp apex_owned_meta?(%SOA{}, _apex_norm), do: true

  defp apex_owned_meta?(%{name: name, __struct__: ExDns.Resource.NS}, apex_norm) do
    canonical(name) == apex_norm
  end

  defp apex_owned_meta?(_, _), do: false

  # ----- triggers ---------------------------------------------------

  defp classify_trigger(name, apex_norm) do
    case strip_apex(canonical(name), apex_norm) do
      nil -> :ignore
      "" -> :ignore
      stem -> stem_to_trigger(stem)
    end
  end

  defp stem_to_trigger("*." <> rest) do
    {:wildcard, rest}
  end

  defp stem_to_trigger(stem) do
    cond do
      String.ends_with?(stem, ".rpz-ip") ->
        case parse_rpz_ip(String.trim_trailing(stem, ".rpz-ip")) do
          {:ok, ip, prefix} -> {:rpz_ip, ip, prefix}
          :error -> {:other, stem}
        end

      String.ends_with?(stem, ".rpz-nsdname") or
        String.ends_with?(stem, ".rpz-nsip") or
          String.ends_with?(stem, ".rpz-client-ip") ->
        {:other, stem}

      true ->
        {:qname, stem}
    end
  end

  # rpz-ip owner format (RFC 8499 §6 / BIND RPZ docs):
  #
  #     <prefix>.<reversed octets>
  #
  # IPv4: `32.1.0.0.10` → 10.0.0.1/32
  # IPv6: `48.zz.0.0.0.0.0.db8.2001` → 2001:db8:: with /48 (using zz to skip elided ::)
  defp parse_rpz_ip(stem) do
    case String.split(stem, ".", trim: true) do
      [prefix_str | rest] ->
        case Integer.parse(prefix_str) do
          {prefix, ""} when prefix in 0..128 ->
            parse_rpz_ip_octets(rest, prefix)

          _ ->
            :error
        end

      _ ->
        :error
    end
  end

  defp parse_rpz_ip_octets(labels, prefix) when length(labels) == 4 do
    # IPv4 — labels are reversed octets.
    case labels |> Enum.reverse() |> Enum.map(&Integer.parse/1) do
      [{a, ""}, {b, ""}, {c, ""}, {d, ""}] when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255 ->
        {:ok, {a, b, c, d}, prefix}

      _ ->
        :error
    end
  end

  defp parse_rpz_ip_octets(labels, prefix) do
    # IPv6 — labels are reversed groups, with `zz` marking
    # the elided `::`.
    parts =
      labels
      |> Enum.reverse()
      |> Enum.map(fn
        "zz" -> :elided
        hex -> hex
      end)

    expand_v6(parts, prefix)
  end

  defp expand_v6(parts, prefix) do
    case Enum.find_index(parts, &(&1 == :elided)) do
      nil ->
        if length(parts) == 8 do
          parse_v6_groups(parts, prefix)
        else
          :error
        end

      idx ->
        before = Enum.slice(parts, 0, idx)
        after_ = Enum.slice(parts, (idx + 1)..-1//1)
        zeros = List.duplicate("0", 8 - length(before) - length(after_))
        parse_v6_groups(before ++ zeros ++ after_, prefix)
    end
  end

  defp parse_v6_groups(groups, prefix) when length(groups) == 8 do
    parsed =
      Enum.map(groups, fn g ->
        case Integer.parse(g, 16) do
          {n, ""} when n in 0..0xFFFF -> n
          _ -> :error
        end
      end)

    if Enum.any?(parsed, &(&1 == :error)) do
      :error
    else
      [a, b, c, d, e, f, g, h] = parsed
      {:ok, {a, b, c, d, e, f, g, h}, prefix}
    end
  end

  defp parse_v6_groups(_, _), do: :error

  # ----- actions ----------------------------------------------------

  defp classify_action(%CNAME{server: target}) do
    case canonical(target) do
      "" -> :nxdomain
      "*" -> :nodata
      "rpz-passthru" -> :passthru
      "rpz-drop" -> :drop
      "rpz-tcp-only" -> :tcp_only
      other -> {:redirect, other}
    end
  end

  defp classify_action(%A{} = a), do: {:synthesise, [a]}
  defp classify_action(%AAAA{} = a), do: {:synthesise, [a]}
  defp classify_action(other), do: {:synthesise, [other]}

  # When multiple synthesised records share the same trigger
  # (e.g. trigger `walled.example.com` has both `A 1.1.1.1` and
  # `AAAA ::1`), merge them into a single rule.
  defp consolidate_synthesised(rules) do
    {synth, rest} =
      Enum.split_with(rules, fn r -> match?(%Rule{action: {:synthesise, _}}, r) end)

    merged =
      synth
      |> Enum.group_by(& &1.trigger)
      |> Enum.map(fn {trigger, group} ->
        records = Enum.flat_map(group, fn %Rule{action: {:synthesise, recs}} -> recs end)
        ttl = group |> Enum.map(& &1.ttl) |> Enum.min()
        %Rule{trigger: trigger, action: {:synthesise, records}, ttl: ttl}
      end)

    rest ++ merged
  end

  # ----- helpers ---------------------------------------------------

  defp strip_apex(name, apex) do
    cond do
      name == apex -> ""
      String.ends_with?(name, "." <> apex) -> String.trim_trailing(name, "." <> apex)
      true -> nil
    end
  end

  defp canonical(name) when is_binary(name) do
    name |> String.downcase(:ascii) |> String.trim_trailing(".")
  end
end
