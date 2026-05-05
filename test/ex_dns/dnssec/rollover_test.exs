defmodule ExDns.DNSSEC.RolloverTest do
  @moduledoc """
  Verifies the ZSK rollover lifecycle: prepare → complete →
  purge. Confirms the keystore reflects each transition and the
  signer correctly switches over to the new key.
  """

  use ExUnit.Case, async: false

  alias ExDns.DNSSEC.{KeyStore, Rollover, Signer, Validator}
  alias ExDns.Resource.{A, DNSKEY}

  setup do
    KeyStore.init()
    KeyStore.clear()
    on_exit(fn -> KeyStore.clear() end)
    :ok
  end

  describe "prepare_zsk_rollover/2" do
    test "stores a new key in the :incoming state" do
      assert {:ok, %DNSKEY{} = dnskey, key_tag} =
               Rollover.prepare_zsk_rollover("example.test")

      assert byte_size(dnskey.public_key) == 64
      assert dnskey.algorithm == 13
      assert dnskey.flags == 256
      assert dnskey.name == "example.test"

      [entry] = KeyStore.keys_for_zone("example.test")
      assert entry.state == :incoming
      assert Validator.key_tag(entry.dnskey) == key_tag
    end

    test "returns {:error, :unsupported_algorithm} for an unknown algorithm" do
      assert {:error, :unsupported_algorithm} =
               Rollover.prepare_zsk_rollover("example.test", algorithm: 99)
    end

    test "supports Ed25519 (algorithm 15)" do
      assert {:ok, %DNSKEY{public_key: pub}, _key_tag} =
               Rollover.prepare_zsk_rollover("example.test", algorithm: 15)

      assert byte_size(pub) == 32
    end
  end

  describe "complete_zsk_rollover/2" do
    test "promotes the staged key and retires every other active key" do
      # Plant an existing active ZSK.
      {:ok, dnskey_old, key_tag_old} = Rollover.prepare_zsk_rollover("example.test")
      :ok = KeyStore.activate_key("example.test", key_tag_old)
      _ = dnskey_old

      # Stage a new one.
      {:ok, _dnskey_new, key_tag_new} = Rollover.prepare_zsk_rollover("example.test")

      # Promote.
      :ok = Rollover.complete_zsk_rollover("example.test", key_tag_new)

      states =
        for entry <- KeyStore.keys_for_zone("example.test"),
            into: %{} do
          {Validator.key_tag(entry.dnskey), entry.state}
        end

      assert states[key_tag_new] == :active
      assert states[key_tag_old] == :retired
    end

    test "returns {:error, :not_found} when the key tag isn't in the keystore" do
      assert {:error, :not_found} =
               Rollover.complete_zsk_rollover("example.test", 12_345)
    end

    test "the signer picks up the new ZSK after promotion" do
      {:ok, _, key_tag_new} = Rollover.prepare_zsk_rollover("example.test")
      :ok = Rollover.complete_zsk_rollover("example.test", key_tag_new)

      # The signing key returned by KeyStore.get_signing_key/1
      # should be the new ZSK.
      %{dnskey: dnskey} = KeyStore.get_signing_key("example.test")
      assert Validator.key_tag(dnskey) == key_tag_new
    end

    test "the new ZSK actually signs records that the validator accepts" do
      {:ok, _, key_tag} = Rollover.prepare_zsk_rollover("example.test")
      :ok = Rollover.complete_zsk_rollover("example.test", key_tag)

      %{dnskey: dnskey, private_key: private_key} = KeyStore.get_signing_key("example.test")

      records = [%A{name: "host.example.test", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}]

      assert {:ok, rrsig} =
               Signer.sign_rrset(records, dnskey, private_key, signer: "example.test")

      assert :ok = Validator.verify_rrset(records, rrsig, dnskey)
    end
  end

  describe "purge_retired_keys/1" do
    test "removes every retired key, leaves others in place" do
      # Active key.
      {:ok, _, active_tag} = Rollover.prepare_zsk_rollover("example.test")
      :ok = KeyStore.activate_key("example.test", active_tag)

      # Two retired keys.
      {:ok, _, retired1} = Rollover.prepare_zsk_rollover("example.test")
      {:ok, _, retired2} = Rollover.prepare_zsk_rollover("example.test")
      :ok = KeyStore.retire_key("example.test", retired1)
      :ok = KeyStore.retire_key("example.test", retired2)

      assert {:ok, 2} = Rollover.purge_retired_keys("example.test")

      remaining_tags =
        for entry <- KeyStore.keys_for_zone("example.test") do
          Validator.key_tag(entry.dnskey)
        end

      assert active_tag in remaining_tags
      refute retired1 in remaining_tags
      refute retired2 in remaining_tags
    end

    test "returns {:ok, 0} when nothing is retired" do
      {:ok, _, _} = Rollover.prepare_zsk_rollover("example.test")
      assert {:ok, 0} = Rollover.purge_retired_keys("example.test")
    end
  end

  test "telemetry events fire for each phase" do
    test_pid = self()

    :telemetry.attach_many(
      "rollover-test",
      [
        [:ex_dns, :dnssec, :rollover, :prepared],
        [:ex_dns, :dnssec, :rollover, :activated],
        [:ex_dns, :dnssec, :rollover, :purged]
      ],
      fn event, _, metadata, _ -> send(test_pid, {event, metadata}) end,
      %{}
    )

    on_exit(fn -> :telemetry.detach("rollover-test") end)

    {:ok, _, key_tag} = Rollover.prepare_zsk_rollover("example.test")
    assert_receive {[:ex_dns, :dnssec, :rollover, :prepared], %{key_tag: ^key_tag}}

    :ok = Rollover.complete_zsk_rollover("example.test", key_tag)
    assert_receive {[:ex_dns, :dnssec, :rollover, :activated], _}

    {:ok, _} = Rollover.purge_retired_keys("example.test")
    assert_receive {[:ex_dns, :dnssec, :rollover, :purged], _}
  end
end
