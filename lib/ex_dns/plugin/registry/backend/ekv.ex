defmodule ExDns.Plugin.Registry.Backend.EKV do
  @moduledoc """
  EKV-backed implementation of `ExDns.Plugin.Registry.Backend`.

  ## Layout

  Two keys, mirroring the persistent-term backend:

  * `plugin/registry`     — `%{slug => entry}` (the
    metadata + module + routes + health + registration index)
  * `plugin/route_index`  — flat list of route records used
    by the resolver hot path

  Both are full-replacement writes — the registry's API
  passes us the complete next-state. CAS is not required:
  the registry serialises mutations through a single
  in-process call site, so the only consistency property
  we need across nodes is "eventual" — every node
  eventually sees the same registry state because the EKV
  layer replicates writes.

  ## Why we still keep the in-process default

  Reads happen on every query that reaches the plugin
  pipeline. EKV's local SQLite shard is fast (microseconds)
  but the in-process `:persistent_term` is faster (single
  process-dictionary read). Single-node deployments that
  don't need cross-node propagation should stay on the
  PersistentTerm backend.

  Operators turn this on when they actually run more than
  one node:

      config :ex_dns, :plugin_registry,
        backend: ExDns.Plugin.Registry.Backend.EKV
  """

  @behaviour ExDns.Plugin.Registry.Backend

  alias ExDns.EKV

  @registry_key "plugin/registry"
  @route_key "plugin/route_index"

  @impl true
  def init, do: :ok

  @impl true
  def registry_state do
    EKV.lookup(@registry_key) || %{}
  end

  @impl true
  def put_registry_state(state) when is_map(state) do
    :ok = EKV.put(@registry_key, state)
    :ok
  end

  @impl true
  def route_index do
    EKV.lookup(@route_key) || []
  end

  @impl true
  def put_route_index(routes) when is_list(routes) do
    :ok = EKV.put(@route_key, routes)
    :ok
  end

  @impl true
  def clear do
    _ = EKV.delete(@registry_key)
    _ = EKV.delete(@route_key)
    :ok
  end
end
