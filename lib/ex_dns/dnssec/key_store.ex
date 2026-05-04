defmodule ExDns.DNSSEC.KeyStore do
  @moduledoc """
  In-process registry of per-zone DNSSEC signing keys.

  A zone's signing material is a `%{zone, dnskey, private_key}` map.
  The `dnskey` is the public-half `%ExDns.Resource.DNSKEY{}` we
  publish in the zone; the `private_key` is the matching private
  half in the format `:crypto.sign/4` expects for the algorithm.

  ## Configuration

  Keys can be installed at boot via:

      config :ex_dns,
        dnssec_keys: [
          %{
            zone: "example.com",
            dnskey: %ExDns.Resource.DNSKEY{...},
            private_key: <<...>>
          }
        ]

  Or programmatically (typically in tests):

      ExDns.DNSSEC.KeyStore.put_key("example.com",
        dnskey: dnskey, private_key: private_key)

  ## Lookup

  Each zone may have multiple keys (KSK + ZSK, key-rollover state).
  `get_signing_key/1` returns the first available key for the zone;
  `keys_for_zone/1` returns the full list.

  """

  alias ExDns.Resource.DNSKEY

  @table :ex_dns_dnssec_keys

  @type entry :: %{
          zone: binary(),
          dnskey: DNSKEY.t(),
          private_key: term()
        }

  @doc "Initialises the registry. Idempotent."
  @spec init() :: :ok
  def init do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [:bag, :public, :named_table, read_concurrency: true])
        load_app_env()
        :ok

      _ ->
        :ok
    end
  end

  defp load_app_env do
    Enum.each(Application.get_env(:ex_dns, :dnssec_keys, []), fn entry ->
      put_key(entry.zone, dnskey: entry.dnskey, private_key: entry.private_key)
    end)
  end

  @doc "Installs a signing key for `zone`."
  @spec put_key(binary(), keyword()) :: :ok
  def put_key(zone, options) when is_binary(zone) do
    init()
    dnskey = Keyword.fetch!(options, :dnskey)
    private_key = Keyword.fetch!(options, :private_key)
    :ets.insert(@table, {normalize(zone), %{dnskey: dnskey, private_key: private_key}})
    :ok
  end

  @doc "Removes every key for `zone`."
  @spec delete_zone(binary()) :: :ok
  def delete_zone(zone) when is_binary(zone) do
    init()
    :ets.delete(@table, normalize(zone))
    :ok
  end

  @doc "Returns every signing-key entry for `zone`."
  @spec keys_for_zone(binary()) :: [entry()]
  def keys_for_zone(zone) when is_binary(zone) do
    init()

    :ets.lookup(@table, normalize(zone))
    |> Enum.map(fn {z, key_map} -> Map.put(key_map, :zone, z) end)
  end

  @doc """
  Returns the first signing key registered for `zone`, or `nil`.

  Useful for the resolver's "do we sign this answer?" check.
  """
  @spec get_signing_key(binary()) :: entry() | nil
  def get_signing_key(zone) when is_binary(zone) do
    case keys_for_zone(zone) do
      [] -> nil
      [first | _] -> first
    end
  end

  @doc "Removes every key from the store."
  @spec clear() :: :ok
  def clear do
    init()
    :ets.delete_all_objects(@table)
    :ok
  end

  defp normalize(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end
end
