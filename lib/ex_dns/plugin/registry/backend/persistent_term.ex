defmodule ExDns.Plugin.Registry.Backend.PersistentTerm do
  @moduledoc """
  Default `ExDns.Plugin.Registry.Backend` implementation —
  in-process, lock-free, single-node.

  Both the registry map and the route index live in
  `:persistent_term`. Writes incur a global VM-wide
  invalidation pulse (which is why we keep them
  infrequent), but reads are essentially free.

  ## When to swap this out

  When you need plugin registrations + route changes to
  propagate across a cluster of ExDns nodes. At that point a
  Raft-or-equivalent backend (EKV, Khepri) replaces this one
  — the registry's public API doesn't change.
  """

  @behaviour ExDns.Plugin.Registry.Backend

  @registry_key {ExDns.Plugin.Registry, :registry}
  @route_key {ExDns.Plugin.Registry, :route_index}

  @impl true
  def init, do: :ok

  @impl true
  def registry_state do
    :persistent_term.get(@registry_key, %{})
  end

  @impl true
  def put_registry_state(state) when is_map(state) do
    :persistent_term.put(@registry_key, state)
    :ok
  end

  @impl true
  def route_index do
    :persistent_term.get(@route_key, [])
  end

  @impl true
  def put_route_index(routes) when is_list(routes) do
    :persistent_term.put(@route_key, routes)
    :ok
  end

  @impl true
  def clear do
    :persistent_term.erase(@registry_key)
    :persistent_term.erase(@route_key)
    :ok
  end
end
