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
end
