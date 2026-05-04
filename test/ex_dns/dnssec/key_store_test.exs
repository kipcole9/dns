defmodule ExDns.DNSSEC.KeyStoreTest do
  use ExUnit.Case, async: false

  alias ExDns.DNSSEC.KeyStore
  alias ExDns.Resource.DNSKEY

  setup do
    KeyStore.init()
    KeyStore.clear()
    on_exit(fn -> KeyStore.clear() end)
    :ok
  end

  defp sample_dnskey do
    {public, _private} = :crypto.generate_key(:ecdh, :secp256r1)
    <<0x04, raw_pub::binary-size(64)>> = public

    %DNSKEY{
      name: "example.com",
      ttl: 86_400,
      class: :in,
      flags: 257,
      protocol: 3,
      algorithm: 13,
      public_key: raw_pub
    }
  end

  test "put_key + get_signing_key round-trips" do
    dnskey = sample_dnskey()
    KeyStore.put_key("example.com", dnskey: dnskey, private_key: <<1, 2, 3>>)

    entry = KeyStore.get_signing_key("example.com")
    assert entry.dnskey == dnskey
    assert entry.private_key == <<1, 2, 3>>
    assert entry.zone == "example.com"
  end

  test "is case-insensitive on the zone name" do
    dnskey = sample_dnskey()
    KeyStore.put_key("EXAMPLE.COM.", dnskey: dnskey, private_key: <<1>>)
    assert KeyStore.get_signing_key("example.com") != nil
  end

  test "keys_for_zone returns all registered keys" do
    dnskey1 = sample_dnskey()
    dnskey2 = sample_dnskey()
    KeyStore.put_key("multi.example", dnskey: dnskey1, private_key: <<1>>)
    KeyStore.put_key("multi.example", dnskey: dnskey2, private_key: <<2>>)

    entries = KeyStore.keys_for_zone("multi.example")
    assert length(entries) == 2
  end

  test "delete_zone removes every key for that zone" do
    KeyStore.put_key("ephemeral.test", dnskey: sample_dnskey(), private_key: <<1>>)
    KeyStore.delete_zone("ephemeral.test")
    assert KeyStore.get_signing_key("ephemeral.test") == nil
  end

  test "get_signing_key returns nil for an unknown zone" do
    assert KeyStore.get_signing_key("nope.example") == nil
  end

  describe "rollover" do
    alias ExDns.DNSSEC.Validator

    test "incoming keys are published but not used for signing" do
      active = sample_dnskey()
      incoming = sample_dnskey()

      KeyStore.put_key("rollover.example", dnskey: active, private_key: <<1>>, state: :active)
      KeyStore.add_key("rollover.example", dnskey: incoming, private_key: <<2>>)

      assert length(KeyStore.published_keys("rollover.example")) == 2
      assert length(KeyStore.signing_keys("rollover.example")) == 1
      assert KeyStore.get_signing_key("rollover.example").dnskey == active
    end

    test "activate_key promotes incoming → active" do
      key = sample_dnskey()
      KeyStore.add_key("rollover.example", dnskey: key, private_key: <<7>>)

      tag = Validator.key_tag(key)
      assert :ok = KeyStore.activate_key("rollover.example", tag)
      assert KeyStore.get_signing_key("rollover.example").dnskey == key
    end

    test "retire_key removes a key from the active set but keeps it published" do
      key = sample_dnskey()
      KeyStore.put_key("rollover.example", dnskey: key, private_key: <<7>>, state: :active)
      tag = Validator.key_tag(key)

      assert :ok = KeyStore.retire_key("rollover.example", tag)
      assert KeyStore.get_signing_key("rollover.example") == nil
      assert length(KeyStore.published_keys("rollover.example")) == 1
    end

    test "remove_key drops a key entirely" do
      key = sample_dnskey()
      KeyStore.put_key("rollover.example", dnskey: key, private_key: <<7>>, state: :retired)
      tag = Validator.key_tag(key)

      assert :ok = KeyStore.remove_key("rollover.example", tag)
      assert KeyStore.published_keys("rollover.example") == []
    end

    test "operations on a missing key tag return {:error, :not_found}" do
      assert {:error, :not_found} = KeyStore.activate_key("nowhere.example", 12_345)
      assert {:error, :not_found} = KeyStore.retire_key("nowhere.example", 12_345)
      assert {:error, :not_found} = KeyStore.remove_key("nowhere.example", 12_345)
    end

    test "two-key rollover: keep old active, add new incoming, activate new, retire old" do
      old_key = sample_dnskey()
      new_key = sample_dnskey()

      KeyStore.put_key("roll.example", dnskey: old_key, private_key: <<1>>, state: :active)
      assert KeyStore.get_signing_key("roll.example").dnskey == old_key

      # Pre-publication
      KeyStore.add_key("roll.example", dnskey: new_key, private_key: <<2>>)
      assert length(KeyStore.signing_keys("roll.example")) == 1

      # Activate new
      KeyStore.activate_key("roll.example", Validator.key_tag(new_key))
      assert length(KeyStore.signing_keys("roll.example")) == 2

      # Retire old
      KeyStore.retire_key("roll.example", Validator.key_tag(old_key))
      assert length(KeyStore.signing_keys("roll.example")) == 1
      assert KeyStore.get_signing_key("roll.example").dnskey == new_key

      # All three states still represented in published set
      assert length(KeyStore.published_keys("roll.example")) == 2
    end
  end
end
