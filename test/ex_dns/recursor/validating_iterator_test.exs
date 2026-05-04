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

  test ":secure when the RRSIG verifies against the cached DNSKEY" do
    {dnskey, private} = make_keypair_with_dnskey("secure.test")
    records = [%A{name: "host.secure.test", ttl: 60, class: :in, ipv4: {9, 9, 9, 9}}]

    {:ok, rrsig} =
      Signer.sign_rrset(records, dnskey, private, signer: "secure.test")

    Cache.put("host.secure.test", :a, records ++ [rrsig], 60)
    Cache.put("secure.test", :dnskey, [dnskey], 86_400)

    assert {:ok, [%A{ipv4: {9, 9, 9, 9}}], :secure} =
             Iterator.resolve_validated("host.secure.test", :a)
  end

  test ":bogus when no DNSKEY matches the RRSIG's key tag" do
    {dnskey, private} = make_keypair_with_dnskey("bogus.test")
    {other_dnskey, _} = make_keypair_with_dnskey("bogus.test")
    records = [%A{name: "host.bogus.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}]

    {:ok, rrsig} =
      Signer.sign_rrset(records, dnskey, private, signer: "bogus.test")

    # Cache an UNRELATED DNSKEY that won't match the rrsig's key_tag.
    refute Validator.key_tag(other_dnskey) == rrsig.key_tag

    Cache.put("host.bogus.test", :a, records ++ [rrsig], 60)
    Cache.put("bogus.test", :dnskey, [other_dnskey], 86_400)

    assert {:ok, _records, :bogus} =
             Iterator.resolve_validated("host.bogus.test", :a)
  end
end
