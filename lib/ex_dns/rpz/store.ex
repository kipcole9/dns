defmodule ExDns.RPZ.Store do
  @moduledoc """
  In-memory store for parsed RPZ rules, exposed through
  `:persistent_term` so per-query reads are lock-free.

  ## API

  * `put/1` replaces the active rule set.
  * `rules/0` returns the active rule set (or `[]` when none
    is loaded).
  * `clear/0` empties the rule set (test helper).

  Updates are atomic from the resolver's point of view — the
  matcher always sees a consistent snapshot.
  """

  alias ExDns.RPZ.Rule

  @key {__MODULE__, :rules}

  @doc """
  Replace the active rule set.

  ### Arguments

  * `rules` — list of `%ExDns.RPZ.Rule{}`.

  ### Returns

  * `:ok`.
  """
  @spec put([Rule.t()]) :: :ok
  def put(rules) when is_list(rules) do
    :persistent_term.put(@key, rules)
  end

  @doc """
  Return the active rule set; `[]` when nothing has been loaded.

  ### Examples

      iex> ExDns.RPZ.Store.clear()
      iex> ExDns.RPZ.Store.rules()
      []

  """
  @spec rules() :: [Rule.t()]
  def rules, do: :persistent_term.get(@key, [])

  @doc "Clear the active rule set. Test helper."
  @spec clear() :: :ok
  def clear do
    _ = :persistent_term.erase(@key)
    :ok
  end
end
