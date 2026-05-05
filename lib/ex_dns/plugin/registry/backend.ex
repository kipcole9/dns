defmodule ExDns.Plugin.Registry.Backend do
  @moduledoc """
  Storage backend behaviour for `ExDns.Plugin.Registry`.

  ## Why a behaviour

  Today the registry's state lives in `:persistent_term` —
  fast, lock-free, and per-node. That's correct for the
  current single-node deployment model, but we want a clean
  swap point for a future clustered build (EKV, Khepri, or
  whatever wins) without rewriting any plugin code.

  This behaviour is the swap point. The default
  implementation is `Registry.Backend.PersistentTerm`. A
  clustered implementation lands when the storage choice is
  made (see the EKV / Khepri research summary in the chat
  thread that introduced this refactor).

  ## State shapes

  Two pieces of state, stored independently because they
  have different read/write rates:

  * **registry**: `%{slug :: atom() => entry :: map()}` —
    every registered plugin (metadata + module + routes +
    health + registration index). Read on the admin API
    + plugin-list paths, written only on register /
    unregister / update_routes / health-flip. Low
    throughput.

  * **route_index**: `[{slug, module, registration_index, route}, ...]`
    — flat list rebuilt from every plugin's routes whenever
    a registration / update_routes / unregister happens.
    Walked on every query that reaches the plugin
    pipeline. High read throughput; updates are bursty.

  Backends MUST keep both stores consistent — a plugin
  appearing in `registry` but not in `route_index` (or vice
  versa) breaks dispatch.
  """

  @type slug :: atom()
  @type entry :: map()
  @type registry_state :: %{slug() => entry()}
  @type route_record :: {slug(), module(), non_neg_integer(), map()}
  @type route_index :: [route_record()]

  @callback init() :: :ok
  @callback registry_state() :: registry_state()
  @callback put_registry_state(registry_state()) :: :ok
  @callback route_index() :: route_index()
  @callback put_route_index(route_index()) :: :ok
  @callback clear() :: :ok

  @doc """
  Returns the configured backend module. Default is
  `ExDns.Plugin.Registry.Backend.PersistentTerm`.

  Override via:

      config :ex_dns, :plugin_registry,
        backend: MyApp.Plugin.Registry.Backend.SomeOtherImpl
  """
  @spec configured() :: module()
  def configured do
    Application.get_env(:ex_dns, :plugin_registry, [])
    |> Keyword.get(:backend, ExDns.Plugin.Registry.Backend.PersistentTerm)
  end
end
