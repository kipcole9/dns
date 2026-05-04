defmodule ExDns.Resolver.DNSSECSigningTest do
  @moduledoc """
  End-to-end resolver test for DNSSEC signing.

  Loads a zone, registers a signing key for it via
  `ExDns.DNSSEC.KeyStore`, sends a query with the DO bit set, and
  asserts that:

  * The response contains an RRSIG for the answer RRset.
  * That RRSIG validates against the matching DNSKEY.

  Queries without the DO bit MUST NOT carry RRSIGs (per RFC 4035 §3).
  """

  use ExUnit.Case, async: false

  alias ExDns.DNSSEC.{KeyStore, Validator}
  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resolver.Default
  alias ExDns.Resource.{A, DNSKEY, OPT, RRSIG, SOA}
  alias ExDns.Storage

  @apex "secure.test"

  setup do
    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)
    KeyStore.init()
    KeyStore.clear()

    on_exit(fn ->
      KeyStore.clear()
      Enum.each(Storage.zones(), &Storage.delete_zone/1)
    end)

    {public, private} = :crypto.generate_key(:ecdh, :secp256r1)
    <<0x04, raw_pub::binary-size(64)>> = public

    dnskey = %DNSKEY{
      name: @apex,
      ttl: 86_400,
      class: :in,
      flags: 257,
      protocol: 3,
      algorithm: 13,
      public_key: raw_pub
    }

    Storage.put_zone(@apex, [
      %SOA{
        name: @apex,
        ttl: 86_400,
        class: :internet,
        mname: "ns.#{@apex}",
        email: "admin.#{@apex}",
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minimum: 3600
      },
      %A{name: @apex, ttl: 60, class: :internet, ipv4: {192, 0, 2, 1}}
    ])

    KeyStore.put_key(@apex, dnskey: dnskey, private_key: private)

    %{dnskey: dnskey}
  end

  defp query(qname, qtype, do_bit?) do
    additional =
      if do_bit? do
        [
          %OPT{
            payload_size: 1232,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: 1,
            z: 0,
            options: []
          }
        ]
      else
        []
      end

    adc = length(additional)

    %Message{
      header: %Header{
        id: 1,
        qr: 0,
        oc: 0,
        aa: 0,
        tc: 0,
        rd: 0,
        ra: 0,
        ad: 0,
        cd: 0,
        rc: 0,
        qc: 1,
        anc: 0,
        auc: 0,
        adc: adc
      },
      question: %Question{host: qname, type: qtype, class: :in},
      answer: [],
      authority: [],
      additional: additional
    }
  end

  test "DO=1 query for an A record gets an answer plus a verifying RRSIG", %{dnskey: dnskey} do
    response = Default.resolve(query(@apex, :a, true))

    assert [%A{ipv4: {192, 0, 2, 1}} = a, %RRSIG{} = rrsig] = response.answer
    assert rrsig.type_covered == :a
    assert rrsig.signer == @apex

    assert :ok = Validator.verify_rrset([a], rrsig, dnskey)
  end

  test "DO=0 query gets no RRSIG (DNSSEC opt-in)" do
    response = Default.resolve(query(@apex, :a, false))

    assert [%A{}] = response.answer
    refute Enum.any?(response.answer, &match?(%RRSIG{}, &1))
  end

  test "DO=1 query for SOA gets a verifying SOA RRSIG", %{dnskey: dnskey} do
    response = Default.resolve(query(@apex, :soa, true))

    [%SOA{} = soa, %RRSIG{} = rrsig] = response.answer
    assert rrsig.type_covered == :soa
    assert :ok = Validator.verify_rrset([soa], rrsig, dnskey)
  end

  test "DO=1 NXDOMAIN response carries an NSEC + RRSIG", %{dnskey: dnskey} do
    response = Default.resolve(query("missing.#{@apex}", :a, true))

    assert response.header.rc == 3

    nsec_records = Enum.filter(response.authority, &match?(%ExDns.Resource.NSEC{}, &1))
    rrsigs = Enum.filter(response.authority, &match?(%RRSIG{}, &1))

    assert length(nsec_records) == 1
    nsec = hd(nsec_records)

    nsec_rrsig = Enum.find(rrsigs, fn r -> r.type_covered == :nsec end)
    assert nsec_rrsig != nil
    assert :ok = Validator.verify_rrset([nsec], nsec_rrsig, dnskey)

    soa_rrsig = Enum.find(rrsigs, fn r -> r.type_covered == :soa end)
    assert soa_rrsig != nil
  end

  test "DO=1 NODATA response carries an NSEC at the queried name", %{dnskey: dnskey} do
    # Query AAAA for the apex (which has only A) → NODATA
    response = Default.resolve(query(@apex, :aaaa, true))

    assert response.header.rc == 0
    assert response.answer == []

    nsec_records = Enum.filter(response.authority, &match?(%ExDns.Resource.NSEC{}, &1))
    assert length(nsec_records) == 1
    nsec = hd(nsec_records)
    # NODATA NSEC is AT the queried name.
    assert nsec.name == @apex

    rrsigs = Enum.filter(response.authority, &match?(%RRSIG{}, &1))
    nsec_rrsig = Enum.find(rrsigs, fn r -> r.type_covered == :nsec end)
    assert :ok = Validator.verify_rrset([nsec], nsec_rrsig, dnskey)
  end
end
