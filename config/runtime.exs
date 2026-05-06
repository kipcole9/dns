###############################################################################
# Bundled `runtime.exs` evaluated by `mix release` at every boot.
#
# Behaviour:
#
#   1. Reads `EXDNS_RUNTIME_CONFIG` (default
#      `/etc/exdns/runtime.exs`).
#   2. If that path exists, merges its contents over the
#      minimal-config defaults from `config/runtime.exs.minimal`.
#   3. Otherwise just uses the minimal-config defaults — the
#      same file the installer drops in place.
#
# This means an operator's edits to `/etc/exdns/runtime.exs`
# override the bundled defaults without anyone having to touch
# the release tree.
###############################################################################

import Config

# Only do real work in production. `mix test` and `mix run`
# in dev evaluate this file too; their config has already
# been loaded from `config/{test,dev}.exs` and we don't want
# to clobber it with the release-shaped defaults.
if config_env() == :prod do

# ----- evaluate the minimal defaults first ---------------------------

minimal_path = Path.join(__DIR__, "runtime.exs.minimal")

if File.regular?(minimal_path) do
  case Config.Reader.read!(minimal_path, env: config_env()) do
    config when is_list(config) ->
      Enum.each(config, fn {app, kw} ->
        Enum.each(kw, fn
          {k, v} when is_atom(k) -> Config.config(app, k, v)
          _ -> :ok
        end)
      end)

    _ ->
      :ok
  end
end

# ----- overlay the operator file (if present) ------------------------

operator_path = System.get_env("EXDNS_RUNTIME_CONFIG", "/etc/exdns/runtime.exs")

if File.regular?(operator_path) do
  case Config.Reader.read!(operator_path, env: config_env()) do
    config when is_list(config) ->
      Enum.each(config, fn {app, kw} ->
        Enum.each(kw, fn
          {k, v} when is_atom(k) -> Config.config(app, k, v)
          _ -> :ok
        end)
      end)

    _ ->
      :ok
  end
end

end

