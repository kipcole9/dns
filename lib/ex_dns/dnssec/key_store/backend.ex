defmodule ExDns.DNSSEC.KeyStore.Backend do
  @moduledoc """
  Storage backend behaviour for `ExDns.DNSSEC.KeyStore`.

  ## Why a behaviour

  DNSSEC signing keys are per-zone state that needs to be
  identical on every node serving the zone — otherwise an
  ANY-cast secondary signs with a key the cluster hasn't
  published. The default backend
  (`ExDns.DNSSEC.KeyStore.Backend.EKV`) stores keys in EKV
  so they replicate cluster-wide. The
  `ExDns.DNSSEC.KeyStore.Backend.ETS` adapter keeps the
  legacy in-process behaviour for single-node deployments
  that prefer to bootstrap keys from configuration.

  ## State shape

  Per zone, a list of entries:

      [%{dnskey: %DNSKEY{}, private_key: term() | nil,
         state: :incoming | :active | :retired}, ...]

  Keys within a zone are uniquely identified by their key
  tag (computed from the DNSKEY).

  ## Configuration

      config :ex_dns, :dnssec_key_store,
        backend: ExDns.DNSSEC.KeyStore.Backend.ETS
  """

  @type entry :: %{
          dnskey: ExDns.Resource.DNSKEY.t(),
          private_key: term() | nil,
          state: :incoming | :active | :retired
        }

  @callback init() :: :ok
  @callback list(zone :: binary()) :: [entry()]
  @callback put_list(zone :: binary(), [entry()]) :: :ok
  @callback delete_zone(zone :: binary()) :: :ok
  @callback all_zones() :: [binary()]
  @callback clear() :: :ok

  @spec configured() :: module()
  def configured do
    Application.get_env(:ex_dns, :dnssec_key_store, [])
    |> Keyword.get(:backend, ExDns.DNSSEC.KeyStore.Backend.EKV)
  end
end
