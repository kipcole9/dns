defmodule ExDns.Plugin do
  @moduledoc """
  Behaviour every in-process ExDns plugin implements.

  ## Why in-process for v1

  The original plan called for plugins to run on separate
  Erlang nodes for crash + memory isolation. That stays the
  long-term direction (see `plans/2026-05-05-ui-policy-plugins-bind-comparison.md`
  §3) — but the immediate goal is to surface plugin-style
  data in the new UI without first standing up a libcluster
  topology. The single-process registry implemented here lets
  a built-in plugin (e.g. the mDNS visualizer) expose itself
  through `/api/v1/plugins` today.

  ## Required callbacks

  * `metadata/0` — static plugin description.

  ## Optional callbacks

  * `get_resource/1` — return the JSON payload for one of the
    plugin's declared `:resources`. Defaults to `:not_found`.
  """

  @type metadata :: %{
          required(:slug) => atom(),
          required(:name) => binary(),
          required(:version) => binary(),
          optional(:ui) => %{
            optional(:title) => binary(),
            optional(:view) => atom(),
            optional(:resources) => [atom()]
          }
        }

  @callback metadata() :: metadata()

  @callback get_resource(atom()) ::
              {:ok, term()} | {:error, :not_found} | {:error, term()}

  @optional_callbacks get_resource: 1
end
