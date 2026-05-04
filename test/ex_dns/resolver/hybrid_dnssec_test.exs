defmodule ExDns.Resolver.HybridDNSSECTest do
  @moduledoc """
  Tests that `ExDns.Resolver.Hybrid` sets the AD (Authentic Data) bit
  on validated DNSSEC responses, and clears it otherwise.

  Recursive resolution is mocked by seeding the recursor cache; this
  test focuses on the AD-bit policy, not on the iterator's
  network-level walk.
  """

  use ExUnit.Case, async: false

  alias ExDns.DNSSEC.Signer
  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Recursor.Cache
  alias ExDns.Resolver.Hybrid
  alias ExDns.Resource.{A, DNSKEY, OPT}
  alias ExDns.Storage

  setup do
    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)
    Cache.init()
    Cache.clear()
    Application.put_env(:ex_dns, :recursion, true)

    on_exit(fn ->
      Application.delete_env(:ex_dns, :recursion)
      Cache.clear()
      Enum.each(Storage.zones(), &Storage.delete_zone/1)
    end)

    :ok
  end

  defp make_keypair(name) do
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

  defp query(qname, qtype, do_bit?) do
    additional =
      if do_bit? do
        [%OPT{payload_size: 1232, extended_rcode: 0, version: 0,
              dnssec_ok: 1, z: 0, options: []}]
      else
        []
      end

    %Message{
      header: %Header{
        id: 1,
        qr: 0,
        oc: 0,
        aa: 0,
        tc: 0,
        rd: 1,
        ra: 0,
        ad: 0,
        cd: 0,
        rc: 0,
        qc: 1,
        anc: 0,
        auc: 0,
        adc: length(additional)
      },
      question: %Question{host: qname, type: qtype, class: :in},
      answer: [],
      authority: [],
      additional: additional
    }
  end

  test "AD=1 when DO=1 and the recursive answer has a verifying RRSIG" do
    {dnskey, private} = make_keypair("secure-recurse.test")
    records = [%A{name: "x.secure-recurse.test", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}]
    {:ok, rrsig} = Signer.sign_rrset(records, dnskey, private, signer: "secure-recurse.test")

    Cache.put("x.secure-recurse.test", :a, records ++ [rrsig], 60)
    Cache.put("secure-recurse.test", :dnskey, [dnskey], 86_400)

    response = Hybrid.resolve(query("x.secure-recurse.test", :a, true))

    assert response.header.ad == 1
    assert response.header.ra == 1
    assert [%A{ipv4: {1, 2, 3, 4}}] = response.answer
  end

  test "AD=0 when DO=0 even if the upstream answer was signed" do
    {dnskey, private} = make_keypair("secure-recurse.test")
    records = [%A{name: "x.secure-recurse.test", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}]
    {:ok, rrsig} = Signer.sign_rrset(records, dnskey, private, signer: "secure-recurse.test")

    Cache.put("x.secure-recurse.test", :a, records ++ [rrsig], 60)
    Cache.put("secure-recurse.test", :dnskey, [dnskey], 86_400)

    response = Hybrid.resolve(query("x.secure-recurse.test", :a, false))

    assert response.header.ad == 0
  end

  test "AD=0 when DO=1 but the answer is unsigned (insecure)" do
    Cache.put("plain.test", :a,
      [%A{name: "plain.test", ttl: 60, class: :in, ipv4: {9, 9, 9, 9}}], 60)

    response = Hybrid.resolve(query("plain.test", :a, true))

    assert response.header.ad == 0
  end

  test "AD=0 when DO=1 but no DNSKEY in cache matches the RRSIG (bogus)" do
    {dnskey, private} = make_keypair("bogus-recurse.test")
    {other_dnskey, _} = make_keypair("bogus-recurse.test")
    records = [%A{name: "x.bogus-recurse.test", ttl: 60, class: :in, ipv4: {5, 5, 5, 5}}]
    {:ok, rrsig} = Signer.sign_rrset(records, dnskey, private, signer: "bogus-recurse.test")

    Cache.put("x.bogus-recurse.test", :a, records ++ [rrsig], 60)
    Cache.put("bogus-recurse.test", :dnskey, [other_dnskey], 86_400)

    response = Hybrid.resolve(query("x.bogus-recurse.test", :a, true))

    assert response.header.ad == 0
  end
end
