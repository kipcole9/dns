defmodule ExDns.DNSSEC.KeyStore do
  @moduledoc """
  In-process registry of per-zone DNSSEC keys with rollover state.

  Each entry holds:

  * `:dnskey` — the public-half `%ExDns.Resource.DNSKEY{}` published
    in the zone.
  * `:private_key` — matching private half (in the format
    `:crypto.sign/4` expects for the algorithm). May be `nil` for
    keys we want to publish for verification but not sign with.
  * `:state` — one of `:incoming`, `:active`, `:retired`. See below.

  ## Rollover lifecycle (RFC 7583)

  ```
                    add_key/2
                       │
                       ▼
                  ┌────────┐  activate_key/2  ┌────────┐  retire_key/2  ┌─────────┐
                  │incoming│ ───────────────▶ │ active │ ─────────────▶ │ retired │
                  └────────┘                  └────────┘                 └─────────┘
                                                                              │
                                                                              ▼
                                                                          remove_key/2
  ```

  * **incoming** — published in the DNSKEY RRset so resolvers can
    cache it, but not yet used for signing. Pre-publication phase.
  * **active** — currently signing. There MAY be more than one
    active key during a rollover.
  * **retired** — no longer signing, still published so cached
    signatures (made before rollover) keep validating.

  Time-based transitions (waiting for cached records to expire) are
  the operator's job; this module only tracks the labels.

  ## Configuration

      config :ex_dns,
        dnssec_keys: [
          %{zone: "example.com", dnskey: …, private_key: …, state: :active}
        ]

  Or programmatically:

      ExDns.DNSSEC.KeyStore.put_key("example.com",
        dnskey: dnskey, private_key: private_key, state: :active)

  ## Lookup

  * `get_signing_key/1` — first `:active` key, used by the signer.
  * `signing_keys/1` — all `:active` keys.
  * `published_keys/1` — every key (any state); these are what go in
    the published DNSKEY RRset.

  """

  alias ExDns.DNSSEC.Validator
  alias ExDns.Resource.DNSKEY

  @table :ex_dns_dnssec_keys

  @type state :: :incoming | :active | :retired

  @type entry :: %{
          zone: binary(),
          dnskey: DNSKEY.t(),
          private_key: term() | nil,
          state: state()
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
      put_key(entry.zone,
        dnskey: entry.dnskey,
        private_key: entry.private_key,
        state: Map.get(entry, :state, :active)
      )
    end)
  end

  @doc """
  Installs a key for `zone`. Use the higher-level `add_key/2` /
  `activate_key/2` for rollover flows; `put_key/2` is the raw setter.

  ### Options

  * `:dnskey` (required) — the public-half DNSKEY.
  * `:private_key` (required, may be `nil`) — the private half.
  * `:state` (default `:active`) — `:incoming`, `:active`, or
    `:retired`.

  """
  @spec put_key(binary(), keyword()) :: :ok
  def put_key(zone, options) when is_binary(zone) do
    init()
    dnskey = Keyword.fetch!(options, :dnskey)
    private_key = Keyword.fetch!(options, :private_key)
    state = Keyword.get(options, :state, :active)

    entry = %{dnskey: dnskey, private_key: private_key, state: state}
    :ets.insert(@table, {normalize(zone), entry})
    :ok
  end

  @doc "Adds a key in the `:incoming` state (pre-publication phase)."
  @spec add_key(binary(), keyword()) :: :ok
  def add_key(zone, options) do
    put_key(zone, Keyword.put(options, :state, :incoming))
  end

  @doc """
  Transitions the key with the given key tag from `:incoming` to
  `:active`. The signer starts using it on the next request.
  """
  @spec activate_key(binary(), non_neg_integer()) :: :ok | {:error, :not_found}
  def activate_key(zone, key_tag) when is_binary(zone) and is_integer(key_tag) do
    update_state(zone, key_tag, :active)
  end

  @doc """
  Transitions the key with the given key tag to `:retired`. The signer
  stops using it; it stays in the published DNSKEY RRset so cached
  pre-rollover signatures still validate.
  """
  @spec retire_key(binary(), non_neg_integer()) :: :ok | {:error, :not_found}
  def retire_key(zone, key_tag) when is_binary(zone) and is_integer(key_tag) do
    update_state(zone, key_tag, :retired)
  end

  @doc "Removes a single key by key tag (state-agnostic)."
  @spec remove_key(binary(), non_neg_integer()) :: :ok | {:error, :not_found}
  def remove_key(zone, key_tag) when is_binary(zone) and is_integer(key_tag) do
    init()
    apex = normalize(zone)

    case find_entry(apex, key_tag) do
      nil ->
        {:error, :not_found}

      entry ->
        :ets.delete_object(@table, {apex, entry})
        :ok
    end
  end

  defp update_state(zone, key_tag, new_state) do
    init()
    apex = normalize(zone)

    case find_entry(apex, key_tag) do
      nil ->
        {:error, :not_found}

      entry ->
        :ets.delete_object(@table, {apex, entry})
        :ets.insert(@table, {apex, %{entry | state: new_state}})
        :ok
    end
  end

  defp find_entry(apex, key_tag) do
    Enum.find_value(:ets.lookup(@table, apex), fn {_zone, entry} ->
      if Validator.key_tag(entry.dnskey) == key_tag, do: entry
    end)
  end

  @doc "Removes every key for `zone`."
  @spec delete_zone(binary()) :: :ok
  def delete_zone(zone) when is_binary(zone) do
    init()
    :ets.delete(@table, normalize(zone))
    :ok
  end

  @doc "Returns every key registered for `zone` (any state)."
  @spec keys_for_zone(binary()) :: [entry()]
  def keys_for_zone(zone) when is_binary(zone) do
    init()

    :ets.lookup(@table, normalize(zone))
    |> Enum.map(fn {z, e} -> Map.put(e, :zone, z) end)
  end

  @doc """
  Returns every key currently published in the zone's DNSKEY RRset
  (incoming + active + retired). Used by the resolver to populate the
  authoritative DNSKEY answer.
  """
  @spec published_keys(binary()) :: [entry()]
  def published_keys(zone), do: keys_for_zone(zone)

  @doc """
  Returns the keys currently signing — the `:active` subset. The
  signer picks one of these.
  """
  @spec signing_keys(binary()) :: [entry()]
  def signing_keys(zone) when is_binary(zone) do
    zone
    |> keys_for_zone()
    |> Enum.filter(&match?(%{state: :active}, &1))
  end

  @doc """
  Returns the first `:active` key registered for `zone`, or `nil` if
  none.
  """
  @spec get_signing_key(binary()) :: entry() | nil
  def get_signing_key(zone) when is_binary(zone) do
    case signing_keys(zone) do
      [] -> nil
      [first | _] -> first
    end
  end

  @doc "Removes every key from the store."
  @spec clear() :: :ok
  def clear do
    init()
    # Same teardown race as `ExDns.Recursor.Cache.clear/0`: in
    # tests an integration test may have stopped the application
    # between `init/0`'s whereis check and `delete_all_objects`,
    # leaving the named-table reference stale. Swallow the
    # ArgumentError defensively — `clear/0` is best-effort.
    try do
      :ets.delete_all_objects(@table)
    rescue
      ArgumentError -> :ok
    end

    :ok
  end

  defp normalize(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end
end
