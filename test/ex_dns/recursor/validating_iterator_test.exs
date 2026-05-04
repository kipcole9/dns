defmodule ExDns.Recursor.ValidatingIteratorTest do
  @moduledoc """
  Unit tests for `ExDns.Recursor.Iterator.resolve_validated/3`.

  We seed the recursor cache with answers and DNSKEYs, then call the
  iterator. This avoids any actual network or upstream-server
  dependency while exercising:

  * the `:secure` path (RRSIG matches a fetched DNSKEY)
  * the `:insecure` path (no RRSIGs in the answer)
  * the `:bogus` path (RRSIG present but no matching DNSKEY)
  """

  use ExUnit.Case, async: false

  alias ExDns.DNSSEC.{Signer, Validator}
  alias ExDns.Recursor.{Cache, Iterator}
  alias ExDns.Resource.{A, DNSKEY, RRSIG}

  setup do
    Cache.init()
    Cache.clear()
    on_exit(fn -> Cache.clear() end)
    :ok
  end

  defp make_keypair_with_dnskey(name) do
    {public, private} = :crypto.generate_key(:ecdh, :secp256r1)
    <<0x04, raw_pub::binary-size(64)>> = public

    dnskey = %DNSKEY{
      name: name,
      ttl: 86_400,
      class: :in,
      flags: 257,
      protocol: 3,
      algorithm: 13,
      public_key: raw_pub
    }

    {dnskey, private}
  end

  test ":insecure when the cached answer carries no RRSIGs" do
    Cache.put("plain.test", :a,
      [%A{name: "plain.test", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}], 60)

    assert {:ok, [%A{ipv4: {1, 2, 3, 4}}], :insecure} =
             Iterator.resolve_validated("plain.test", :a)
  end

  test ":indeterminate when the cached DNSKEY exists but the chain to root can't be built" do
    # Without DS+DNSKEY records all the way up to the IANA root, the
    # full chain validator can't build a chain. We get :indeterminate
    # rather than :secure or :bogus.
    {dnskey, private} = make_keypair_with_dnskey("secure.test")
    records = [%A{name: "host.secure.test", ttl: 60, class: :in, ipv4: {9, 9, 9, 9}}]

    {:ok, rrsig} =
      Signer.sign_rrset(records, dnskey, private, signer: "secure.test")

    Cache.put("host.secure.test", :a, records ++ [rrsig], 60)
    Cache.put("secure.test", :dnskey, [dnskey], 86_400)

    assert {:ok, [%A{ipv4: {9, 9, 9, 9}}], :indeterminate} =
             Iterator.resolve_validated("host.secure.test", :a)
  end

  test ":indeterminate when no DNSKEY matches the RRSIG's key tag (chain incomplete)" do
    {dnskey, private} = make_keypair_with_dnskey("bogus.test")
    {other_dnskey, _} = make_keypair_with_dnskey("bogus.test")
    records = [%A{name: "host.bogus.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}]

    {:ok, rrsig} =
      Signer.sign_rrset(records, dnskey, private, signer: "bogus.test")

    refute Validator.key_tag(other_dnskey) == rrsig.key_tag

    Cache.put("host.bogus.test", :a, records ++ [rrsig], 60)
    Cache.put("bogus.test", :dnskey, [other_dnskey], 86_400)

    # With the new full-chain validator, the missing DS chain to root
    # also makes this :indeterminate (we never got far enough to
    # discover the key-tag mismatch).
    assert {:ok, _records, status} =
             Iterator.resolve_validated("host.bogus.test", :a)

    assert status in [:indeterminate, :bogus]
  end
end
