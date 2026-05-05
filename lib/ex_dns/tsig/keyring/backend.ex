defmodule ExDns.TSIG.Keyring.Backend do
  @moduledoc """
  Storage backend for runtime-installed TSIG keys.

  Static keys configured under `:ex_dns, :tsig_keys` are
  *always* read directly from Application env — that's the
  declarative config path and it stays per-node.

  Runtime-installed keys (via `Keyring.put/3`, the admin
  API, or future UI flows) go through this backend so they
  can be cluster-replicated when EKV is in play.

  ## Default

  `ExDns.TSIG.Keyring.Backend.EKV` — same code path single-
  node and clustered. Operators wanting strictly per-node
  runtime keys override:

      config :ex_dns, :tsig_keyring,
        backend: ExDns.TSIG.Keyring.Backend.ETS
  """

  @type entry :: %{algorithm: binary(), secret: binary()}

  @callback init() :: :ok
  @callback lookup(name :: binary()) :: {:ok, entry()} | :error
  @callback put(name :: binary(), entry()) :: :ok
  @callback delete(name :: binary()) :: :ok
  @callback all() :: [{binary(), entry()}]

  @spec configured() :: module()
  def configured do
    Application.get_env(:ex_dns, :tsig_keyring, [])
    |> Keyword.get(:backend, ExDns.TSIG.Keyring.Backend.EKV)
  end
end
