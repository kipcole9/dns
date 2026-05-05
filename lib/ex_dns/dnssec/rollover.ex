defmodule ExDns.DNSSEC.Rollover do
  @moduledoc """
  DNSKEY rollover automation for ZSKs (Zone Signing Keys),
  following the pre-publish strategy described in RFC 7583 §3.2.

  ## ZSK rollover phases

      time ->
       ┌──────────┬──────────┬──────────┐
       │ pre-pub  │ ready    │ retire   │
       │ (incoming)         │ (active) │ (retired) │
       └──────────┴──────────┴──────────┘
        publish    swap        purge
        new ZSK    signing     old ZSK
                   to new ZSK

  Each phase is bounded by the *propagation TTL*: how long the
  zone's DNSKEY RRset takes to flush from caches. The minimum
  safe gap between `prepare_zsk_rollover/1` and
  `complete_zsk_rollover/2` is `max(DNSKEY_TTL, RRSIG_TTL) +
  propagation_delay`. Past the swap, leave the retired key in
  the DNSKEY RRset for the same window so any signatures still
  cached at validators continue to verify.

  ## Manual vs. automatic

  This module provides three callable phases. Production
  deployments wire them to a scheduler (cron, oban, a custom
  GenServer); a built-in scheduler is a follow-up.

  ## KSK rollover

  Three-phase pre-publish rollover, mirroring the ZSK lifecycle
  but with two extras:

  1. KSK gets DNSKEY flags `257` (Secure Entry Point bit set)
     instead of the ZSK's `256`.
  2. The child zone publishes CDS + CDNSKEY records (RFC 7344)
     so a parent that polls them auto-updates its DS set
     without manual coordination. `cds_records_for/2` and
     `cdnskey_records_for/2` build the RRsets at any time;
     callers (the resolver, an admin handler) decide when to
     emit them.

  Phases:

  * `prepare_ksk_rollover/2` — generate + stage a new KSK as
    `:incoming`. Publish DNSKEY RRset including the new key for
    one TTL window so validators cache it.
  * `complete_ksk_rollover/2` — activate the new KSK, retire
    the old. The child's CDS/CDNSKEY now advertise the new key.
  * `purge_retired_keys/1` — same call as ZSK (state-based,
    works for both). Optionally followed by emitting RFC 8078
    `delete`-form CDS/CDNSKEY when removing the last KSK.
  """

  alias ExDns.DNSSEC.KeyStore
  alias ExDns.DNSSEC.Validator
  alias ExDns.Message
  alias ExDns.Resource.{CDNSKEY, CDS, DNSKEY}

  require Logger

  # Default ZSK: ECDSA P-256 (algorithm 13). Algorithm choice is
  # configurable per-call.
  @default_algorithm 13

  @doc """
  Generate a new ZSK and stage it in the `:incoming` state for
  `zone`.

  The signer doesn't pick up `:incoming` keys, but the published
  DNSKEY RRset includes them so validators get a chance to cache
  the new key before it starts producing signatures.

  ### Arguments

  * `zone` is the apex (binary).

  * `options` is a keyword list:

  ### Options

  * `:algorithm` — DNSSEC algorithm number. Defaults to `13`
    (ECDSA P-256/SHA-256).

  * `:flags` — DNSKEY flags. Defaults to `256` (ZSK; bit 7 unset
    → not a Secure Entry Point).

  ### Returns

  * `{:ok, dnskey, key_tag}` — the new public DNSKEY plus its
    computed key tag.

  * `{:error, :unsupported_algorithm}` — when `:algorithm` isn't
    one we can generate.

  ### Examples

      iex> ExDns.DNSSEC.KeyStore.clear()
      iex> {:ok, %ExDns.Resource.DNSKEY{}, _} =
      ...>   ExDns.DNSSEC.Rollover.prepare_zsk_rollover("example.test")

  """
  @spec prepare_zsk_rollover(binary(), keyword()) ::
          {:ok, DNSKEY.t(), non_neg_integer()} | {:error, :unsupported_algorithm}
  def prepare_zsk_rollover(zone, options \\ []) when is_binary(zone) do
    algorithm = Keyword.get(options, :algorithm, @default_algorithm)
    flags = Keyword.get(options, :flags, 256)

    case generate_keypair(algorithm) do
      {:ok, dnskey_template, private_key} ->
        dnskey = %DNSKEY{
          dnskey_template
          | name: zone,
            ttl: 86_400,
            class: :in,
            flags: flags,
            protocol: 3,
            algorithm: algorithm
        }

        key_tag = Validator.key_tag(dnskey)

        :ok =
          KeyStore.add_key(zone,
            dnskey: dnskey,
            private_key: private_key
          )

        Logger.info("ExDns.DNSSEC.Rollover[#{zone}]: prepared incoming ZSK key_tag=#{key_tag}")

        :telemetry.execute(
          [:ex_dns, :dnssec, :rollover, :prepared],
          %{count: 1},
          %{zone: zone, key_tag: key_tag, algorithm: algorithm}
        )

        {:ok, dnskey, key_tag}

      {:error, _} = err ->
        err
    end
  end

  @doc """
  Promote the staged key to `:active` and retire every other
  active ZSK in `zone`.

  Signing immediately starts using the new key. Existing signatures
  using the retired keys remain valid until they expire from
  validator caches; the retired keys stay in the DNSKEY RRset so
  those signatures continue to verify.

  ### Arguments

  * `zone` — the apex.
  * `new_key_tag` — the key tag returned by
    `prepare_zsk_rollover/1`.

  ### Returns

  * `:ok`.
  * `{:error, :not_found}` — `new_key_tag` isn't in the keystore.
  """
  @spec complete_zsk_rollover(binary(), non_neg_integer()) :: :ok | {:error, :not_found}
  def complete_zsk_rollover(zone, new_key_tag) do
    case KeyStore.activate_key(zone, new_key_tag) do
      :ok ->
        # Retire every other ACTIVE key for this zone so signing
        # only happens with the new one going forward.
        for entry <- KeyStore.keys_for_zone(zone),
            entry.state == :active,
            Validator.key_tag(entry.dnskey) != new_key_tag do
          KeyStore.retire_key(zone, Validator.key_tag(entry.dnskey))
        end

        Logger.info("ExDns.DNSSEC.Rollover[#{zone}]: activated ZSK key_tag=#{new_key_tag}")

        :telemetry.execute(
          [:ex_dns, :dnssec, :rollover, :activated],
          %{count: 1},
          %{zone: zone, key_tag: new_key_tag}
        )

        :ok

      {:error, _} = err ->
        err
    end
  end

  @doc """
  Permanently remove every retired key from `zone`. Run after
  enough time has passed that no validator can still hold a
  signature made with those keys.

  ### Arguments

  * `zone` — the apex.

  ### Returns

  * `{:ok, removed}` — count of keys purged.
  """
  @spec purge_retired_keys(binary()) :: {:ok, non_neg_integer()}
  def purge_retired_keys(zone) when is_binary(zone) do
    retired_tags =
      for entry <- KeyStore.keys_for_zone(zone),
          entry.state == :retired do
        Validator.key_tag(entry.dnskey)
      end

    Enum.each(retired_tags, fn tag -> KeyStore.remove_key(zone, tag) end)

    Logger.info(
      "ExDns.DNSSEC.Rollover[#{zone}]: purged #{length(retired_tags)} retired ZSKs"
    )

    :telemetry.execute(
      [:ex_dns, :dnssec, :rollover, :purged],
      %{count: length(retired_tags)},
      %{zone: zone}
    )

    {:ok, length(retired_tags)}
  end

  # ----- KSK rollover ----------------------------------------------

  @doc """
  Generate a new KSK and stage it in the `:incoming` state for
  `zone`.

  Identical to `prepare_zsk_rollover/2` except the DNSKEY flags
  default to `257` (Secure Entry Point bit set), marking the
  key as a KSK.

  ### Arguments

  * `zone` — the apex.
  * `options` — same keys as `prepare_zsk_rollover/2`.
    `:flags` defaults to `257` here.

  ### Returns

  * `{:ok, dnskey, key_tag}` — the new KSK + its key tag.
  * `{:error, :unsupported_algorithm}`.
  """
  @spec prepare_ksk_rollover(binary(), keyword()) ::
          {:ok, DNSKEY.t(), non_neg_integer()} | {:error, :unsupported_algorithm}
  def prepare_ksk_rollover(zone, options \\ []) when is_binary(zone) do
    options = Keyword.put_new(options, :flags, 257)
    prepare_zsk_rollover(zone, options)
  end

  @doc """
  Promote the staged KSK to `:active` and retire every other
  active KSK in `zone`. After this, `cds_records_for/2` and
  `cdnskey_records_for/2` advertise the new key.

  ### Arguments

  * `zone` — the apex.
  * `new_key_tag` — the key tag returned by
    `prepare_ksk_rollover/2`.

  ### Returns

  * `:ok` or `{:error, :not_found}`.
  """
  @spec complete_ksk_rollover(binary(), non_neg_integer()) :: :ok | {:error, :not_found}
  def complete_ksk_rollover(zone, new_key_tag) do
    # Same state mechanics as ZSK; the only material difference
    # is which keys we retire (KSKs are flagged 257 vs ZSK's 256).
    case KeyStore.activate_key(zone, new_key_tag) do
      :ok ->
        for entry <- KeyStore.keys_for_zone(zone),
            entry.state == :active,
            entry.dnskey.flags == 257,
            Validator.key_tag(entry.dnskey) != new_key_tag do
          KeyStore.retire_key(zone, Validator.key_tag(entry.dnskey))
        end

        :telemetry.execute(
          [:ex_dns, :dnssec, :rollover, :activated],
          %{count: 1},
          %{zone: zone, key_tag: new_key_tag, kind: :ksk}
        )

        :ok

      {:error, _} = err ->
        err
    end
  end

  # ----- CDS / CDNSKEY publication ---------------------------------

  @doc """
  Build CDS records (RFC 7344) for every active KSK in `zone`.

  Publish these in the child zone so a CDS-aware parent picks
  up the new DS set automatically during a KSK rollover. Use
  digest type SHA-256 (`2`) — the universally-deployed choice.

  ### Arguments

  * `zone` — the apex.
  * `options` — keyword list:

  ### Options

  * `:digest_type` — `1` (SHA-1) or `2` (SHA-256, default).
  * `:ttl` — defaults to `3600`.

  ### Returns

  * `[%CDS{}, ...]`. May be empty if no active KSKs are
    registered.

  ### Examples

      iex> ExDns.DNSSEC.KeyStore.clear()
      iex> ExDns.DNSSEC.Rollover.cds_records_for("example.test")
      []

  """
  @spec cds_records_for(binary(), keyword()) :: [%CDS{}]
  def cds_records_for(zone, options \\ []) when is_binary(zone) do
    digest_type = Keyword.get(options, :digest_type, 2)
    ttl = Keyword.get(options, :ttl, 3600)

    for entry <- KeyStore.keys_for_zone(zone),
        entry.state == :active,
        entry.dnskey.flags == 257 do
      digest = compute_ds_digest(zone, entry.dnskey, digest_type)

      %CDS{
        name: zone,
        ttl: ttl,
        class: :in,
        key_tag: Validator.key_tag(entry.dnskey),
        algorithm: entry.dnskey.algorithm,
        digest_type: digest_type,
        digest: digest
      }
    end
  end

  @doc """
  Build CDNSKEY records (RFC 7344) for every active KSK in
  `zone`. CDNSKEY is wire-identical to DNSKEY; the published
  key set tells a parent "if you want to pick the digest
  yourself, here are the keys".

  ### Arguments

  * `zone` — the apex.
  * `options` — keyword list. `:ttl` defaults to `3600`.

  ### Returns

  * `[%CDNSKEY{}, ...]`. May be empty.
  """
  @spec cdnskey_records_for(binary(), keyword()) :: [%CDNSKEY{}]
  def cdnskey_records_for(zone, options \\ []) when is_binary(zone) do
    ttl = Keyword.get(options, :ttl, 3600)

    for entry <- KeyStore.keys_for_zone(zone),
        entry.state == :active,
        entry.dnskey.flags == 257 do
      %CDNSKEY{
        name: zone,
        ttl: ttl,
        class: :in,
        flags: entry.dnskey.flags,
        protocol: entry.dnskey.protocol,
        algorithm: entry.dnskey.algorithm,
        public_key: entry.dnskey.public_key
      }
    end
  end

  # Compute a DS-style digest of `dnskey` per RFC 4034 §5.1.4:
  # SHA-1 (digest_type 1) or SHA-256 (digest_type 2) over
  # `canonical_owner_name || rdata`.
  defp compute_ds_digest(zone, %DNSKEY{} = dnskey, digest_type) do
    owner = Message.encode_name(String.downcase(zone, :ascii))

    rdata =
      <<dnskey.flags::size(16), dnskey.protocol::size(8), dnskey.algorithm::size(8),
        dnskey.public_key::binary>>

    case digest_type do
      1 -> :crypto.hash(:sha, owner <> rdata)
      2 -> :crypto.hash(:sha256, owner <> rdata)
    end
  end

  # ----- internals -------------------------------------------------

  # Generate a fresh keypair for the requested DNSSEC algorithm,
  # returning a partial DNSKEY struct (just the public_key field
  # populated) plus the matching private key.
  defp generate_keypair(13) do
    # ECDSA P-256.
    {public, private} = :crypto.generate_key(:ecdh, :secp256r1)
    <<0x04, raw_pub::binary-size(64)>> = public
    {:ok, %DNSKEY{public_key: raw_pub}, private}
  end

  defp generate_keypair(15) do
    # Ed25519.
    {public, private} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, %DNSKEY{public_key: public}, private}
  end

  defp generate_keypair(_), do: {:error, :unsupported_algorithm}
end
