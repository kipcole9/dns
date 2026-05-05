defmodule ExDns.Plugin.Action do
  @moduledoc """
  Behaviour for plugins that accept mutating HTTP actions from
  the UI.

  Wired into the API at:

      POST /api/v1/plugins/:slug/actions/:name

  The router decodes the JSON body, calls
  `plugin_module.handle_action(name, params)`, and returns
  the function's `{:ok, payload}` / `{:error, reason}` straight
  through. Auth requires the `zone_admin` role and a scope
  of `"plugin:" <> slug`.

  Plugins that don't need mutations skip this behaviour
  entirely.
  """

  @callback handle_action(name :: binary(), params :: map()) ::
              {:ok, map()} | {:error, term()}
end
