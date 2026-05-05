defmodule ExDns.BlackHole.Set do
  @moduledoc """
  Compiled domain-match set for BlackHole.

  ## Shape

  Two `MapSet`s plus an optional regex list:

  * `:exact` — domains that must match the qname exactly
    (e.g. `tracker.example.com`).
  * `:suffixes` — domains that match the qname or any of its
    descendants (the standard pi-hole `*.x.y` wildcard
    semantics expressed as a label-walk: a qname matches if
    any of its ancestors is in the set).
  * `:regex` — list of compiled `Regex.t()` patterns; tried
    last when neither the exact set nor the suffix walk
    matched. Operators add these sparingly; large regex lists
    dominate the per-query cost.

  ## Lookup

  `match?(set, qname)` is O(label-count) for the exact +
  suffix walk plus a linear pass over `:regex`. With realistic
  blocklist sizes (~1M domains, single-digit regex entries)
  the median per-query cost is microseconds.

  ## Storage

  The compiled set lives in `:persistent_term` so reads on
  the resolver hot path are lock-free. `install/1` swaps the
  reference atomically.
  """

  @key {__MODULE__, :compiled}

  @type t :: %{exact: MapSet.t(), suffixes: MapSet.t(), regex: [Regex.t()]}

  @doc "Build a compiled set from raw domain entries."
  @spec compile([binary()]) :: t()
  def compile(entries) when is_list(entries) do
    {exact, suffixes, regex} =
      Enum.reduce(entries, {[], [], []}, fn entry, {ex, sf, rx} ->
        case classify(entry) do
          {:exact, domain} -> {[domain | ex], sf, rx}
          {:suffix, domain} -> {ex, [domain | sf], rx}
          {:regex, pattern} -> {ex, sf, [pattern | rx]}
          :skip -> {ex, sf, rx}
        end
      end)

    %{
      exact: MapSet.new(exact),
      suffixes: MapSet.new(suffixes),
      regex: Enum.reverse(regex)
    }
  end

  @doc """
  Install `set` into `:persistent_term`. Reads via `current/0`
  return this set until another `install/1`.
  """
  @spec install(t()) :: :ok
  def install(set) do
    :persistent_term.put(@key, set)
    :ok
  end

  @doc "Return the currently-installed set, or an empty one when none has been installed."
  @spec current() :: t()
  def current do
    :persistent_term.get(@key, %{exact: MapSet.new(), suffixes: MapSet.new(), regex: []})
  end

  @doc """
  Return `true` when `qname` matches the compiled set.

  Walk: exact match on `qname` itself, then walk up to the apex
  trying each ancestor against the suffix set; finally try the
  regex list.
  """
  @spec match?(t(), binary()) :: boolean()
  def match?(set, qname) when is_binary(qname) do
    norm = normalise(qname)

    cond do
      MapSet.member?(set.exact, norm) ->
        true

      walk_suffixes(norm, set.suffixes) ->
        true

      Enum.any?(set.regex, &Regex.match?(&1, norm)) ->
        true

      true ->
        false
    end
  end

  @doc "Empty the installed set. Test helper."
  @spec clear() :: :ok
  def clear do
    :persistent_term.erase(@key)
    :ok
  end

  # ----- internals --------------------------------------------------

  # Walks the qname up to the apex, returning true if any of
  # its labels (or the qname itself) sits in the suffix set.
  defp walk_suffixes(qname, suffixes) do
    cond do
      MapSet.member?(suffixes, qname) ->
        true

      qname == "" ->
        false

      true ->
        case String.split(qname, ".", parts: 2) do
          [_, parent] -> walk_suffixes(parent, suffixes)
          [_only] -> false
        end
    end
  end

  defp classify(entry) when is_binary(entry) do
    trimmed = String.trim(entry)

    cond do
      trimmed == "" -> :skip
      String.starts_with?(trimmed, "/") and String.ends_with?(trimmed, "/") ->
        body = String.slice(trimmed, 1..-2//1)

        case Regex.compile(body) do
          {:ok, regex} -> {:regex, regex}
          {:error, _} -> :skip
        end

      String.starts_with?(trimmed, "*.") ->
        {:suffix, normalise(String.slice(trimmed, 2..-1//1))}

      true ->
        {:exact, normalise(trimmed)}
    end
  end

  defp normalise(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end
end
