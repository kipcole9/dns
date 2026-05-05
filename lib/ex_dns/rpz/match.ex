defmodule ExDns.RPZ.Match do
  @moduledoc """
  Match a query name against a parsed RPZ rule set.

  The runtime counterpart to `ExDns.RPZ` (the parser). Given a
  list of `%ExDns.RPZ.Rule{}` and a qname, returns the first
  matching rule, or `:no_match` when none of the qname-based
  triggers fire.

  ## Match precedence

  RFC 8499 / BIND RPZ semantics: **most-specific-trigger wins**,
  with exact-qname triggers preferred over wildcards. Within
  each tier, source order in the rule list breaks ties.

  ## Triggers handled

  * `{:qname, name}` — exact (case-insensitive) qname match.
  * `{:wildcard, name}` — qname is `name` itself OR an
    immediate child label.

  Other triggers (`:rpz_ip`, `:other`) are out of scope for
  this matcher — `:rpz_ip` requires inspecting the *response*
  not the qname, and the matchers for those plug in at a
  different point in the resolver pipeline.
  """

  alias ExDns.RPZ.Rule

  @doc """
  Look up the first matching rule for `qname` in `rules`.

  ### Arguments

  * `qname` — the query name (binary).
  * `rules` — list of `%ExDns.RPZ.Rule{}` from
    `ExDns.RPZ.parse/2`.

  ### Returns

  * `{:match, rule}` when a qname / wildcard rule matches.
  * `:no_match` otherwise.

  ### Examples

      iex> ExDns.RPZ.Match.find("anything.test", [])
      :no_match

  """
  @spec find(binary(), [Rule.t()]) :: {:match, Rule.t()} | :no_match
  def find(qname, rules) when is_binary(qname) and is_list(rules) do
    qname_norm = canonical(qname)

    case exact_match(qname_norm, rules) do
      {:match, _} = hit -> hit
      :no_match -> wildcard_match(qname_norm, rules)
    end
  end

  defp exact_match(qname_norm, rules) do
    Enum.find(rules, fn
      %Rule{trigger: {:qname, name}} -> canonical(name) == qname_norm
      _ -> false
    end)
    |> wrap()
  end

  defp wildcard_match(qname_norm, rules) do
    Enum.find(rules, fn
      %Rule{trigger: {:wildcard, name}} -> qname_under?(qname_norm, canonical(name))
      _ -> false
    end)
    |> wrap()
  end

  defp wrap(nil), do: :no_match
  defp wrap(%Rule{} = rule), do: {:match, rule}

  # `*.foo.test` matches `foo.test`, `bar.foo.test`,
  # `baz.bar.foo.test`, etc. — anything at or below `foo.test`.
  defp qname_under?(qname, base) do
    qname == base or String.ends_with?(qname, "." <> base)
  end

  defp canonical(name) when is_binary(name) do
    name |> String.downcase(:ascii) |> String.trim_trailing(".")
  end
end
