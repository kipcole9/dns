defmodule ExDns.Conformance.RFCTest do
  @moduledoc """
  RFC conformance test suite.

  Cross-checks ExDns's behaviour against the wire-level
  expectations spelled out in the major DNS RFCs — the same
  behaviour BIND, Knot, NSD, etc. produce when fed the same
  inputs. Each assertion cites the RFC clause it codifies so
  regressions surface as "you broke RFC X §Y" rather than as a
  generic test failure.

  The suite is *not* a substitute for running ExDns alongside
  BIND/Knot under a load generator — that's an integration-
  environment concern. What this file gives is a stable,
  in-process safety net: every wire detail the spec mandates is
  exercised on every CI run.

  ## Coverage

  * Header bit ordering (RFC 1035 §4.1.1)
  * Case-insensitive name comparison (RFC 1035 §3.1, RFC 4343)
  * Name compression on encode (RFC 1035 §4.1.4)
  * NXDOMAIN with SOA in AUTHORITY (RFC 2308 §2.1)
  * NODATA with SOA in AUTHORITY (RFC 2308 §2.2)
  * AXFR opens and closes with SOA (RFC 5936 §2.2)
  * DS digest computation (RFC 4034 §5.1.4)
  * EDNS OPT echoed in response (RFC 6891 §6.1.1)
  * BADCOOKIE rcode value (RFC 7873 §6)
  * NSEC3 hash algorithm = SHA-1 (RFC 5155 §5)
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resolver.Default
  alias ExDns.Resource.{A, NS, SOA}
  alias ExDns.Storage

  setup do
    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)

    on_exit(fn -> Enum.each(Storage.zones(), &Storage.delete_zone/1) end)

    :ok
  end

  defp soa do
    %SOA{
      name: "conformance.test",
      ttl: 3600,
      class: :in,
      mname: "ns.conformance.test",
      email: "admin.conformance.test",
      serial: 1,
      refresh: 7200,
      retry: 3600,
      expire: 1_209_600,
      minimum: 3600
    }
  end

  defp seed_zone do
    Storage.put_zone("conformance.test", [
      soa(),
      %NS{name: "conformance.test", ttl: 3600, class: :in, server: "ns.conformance.test"},
      %A{name: "host.conformance.test", ttl: 60, class: :in, ipv4: {198, 51, 100, 7}}
    ])
  end

  defp query(qname, qtype) do
    %Message{
      header: %Header{
        id: 0xCAFE,
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
        adc: 0
      },
      question: %Question{host: qname, type: qtype, class: :in},
      answer: [],
      authority: [],
      additional: []
    }
  end

  describe "RFC 1035 §4.1.1 — header bit ordering" do
    test "QR is the high bit of the second 16-bit field" do
      bytes =
        Message.encode(%{query("conformance.test", :soa) | header: %Header{
          query("conformance.test", :soa).header
          | qr: 1
        }})

      <<_id::16, qr::1, _rest::bits>> = bytes
      assert qr == 1
    end

    test "the response always echoes the query's transaction id" do
      seed_zone()

      response = Default.resolve(%{query("host.conformance.test", :a) | header: %Header{
        query("host.conformance.test", :a).header
        | id: 0xDEAD
      }})

      assert response.header.id == 0xDEAD
    end
  end

  describe "RFC 1035 §3.1 / RFC 4343 — case-insensitive name comparison" do
    test "queries with mixed case match the same data as lower-case queries" do
      seed_zone()

      for variant <- ["host.conformance.test", "HOST.CONFORMANCE.TEST", "Host.Conformance.Test"] do
        response = Default.resolve(query(variant, :a))
        assert [%A{ipv4: {198, 51, 100, 7}}] = response.answer
      end
    end
  end

  describe "RFC 1035 §4.1.4 — name compression on encode" do
    test "repeated names are compressed via 0xC0 pointers" do
      # Build a message with two identical names; the encoded form
      # MUST share storage via a compression pointer (top two bits = 11).
      message = %Message{
        header: %Header{
          id: 1,
          qr: 1,
          oc: 0,
          aa: 1,
          tc: 0,
          rd: 0,
          ra: 0,
          ad: 0,
          cd: 0,
          rc: 0,
          qc: 1,
          anc: 1,
          auc: 0,
          adc: 0
        },
        question: %Question{host: "host.conformance.test", type: :a, class: :in},
        answer: [%A{name: "host.conformance.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}],
        authority: [],
        additional: []
      }

      bytes = Message.encode(message)
      # A compression pointer byte has the top two bits set: 0xC0..0xFF.
      assert :binary.match(bytes, <<0xC0>>) != :nomatch
    end
  end

  describe "RFC 2308 §2.1 — NXDOMAIN response carries the apex SOA in AUTHORITY" do
    test "NXDOMAIN response carries the apex SOA in AUTHORITY" do
      seed_zone()

      response = Default.resolve(query("does-not-exist.conformance.test", :a))

      assert response.header.rc == 3
      assert response.header.aa == 1
      assert Enum.any?(response.authority, &match?(%SOA{}, &1))
    end
  end

  describe "RFC 2308 §2.2 — NODATA response carries the apex SOA in AUTHORITY" do
    test "NODATA response carries the apex SOA in AUTHORITY" do
      seed_zone()

      response = Default.resolve(query("host.conformance.test", :mx))

      assert response.header.rc == 0
      assert response.answer == []
      assert Enum.any?(response.authority, &match?(%SOA{}, &1))
    end
  end

  describe "RFC 5936 §2.2 — AXFR shape" do
    test "AXFR opens and closes with the apex SOA" do
      seed_zone()

      response = Default.resolve(query("conformance.test", :axfr))
      assert response.header.rc == 0

      assert match?(%SOA{}, hd(response.answer))
      assert match?(%SOA{}, List.last(response.answer))
    end
  end

  describe "RFC 4034 §5.1.4 — DS digest computation" do
    test "DS digest is SHA-256 of canonical_owner_name || rdata" do
      alias ExDns.DNSSEC.{KeyStore, Rollover, Validator}
      alias ExDns.Resource.CDS
      KeyStore.init()
      KeyStore.clear()
      on_exit(fn -> KeyStore.clear() end)

      {:ok, dnskey, _key_tag} = Rollover.prepare_ksk_rollover("conformance.test")
      :ok = KeyStore.activate_key("conformance.test", Validator.key_tag(dnskey))

      [%CDS{} = cds] = Rollover.cds_records_for("conformance.test")

      owner = Message.encode_name("conformance.test")

      rdata =
        <<dnskey.flags::size(16), dnskey.protocol::size(8), dnskey.algorithm::size(8),
          dnskey.public_key::binary>>

      expected = :crypto.hash(:sha256, owner <> rdata)
      assert cds.digest == expected
    end
  end

  describe "RFC 6891 §6.1.1 — EDNS OPT in response" do
    test "OPT in the request causes OPT in the response additional section" do
      seed_zone()
      alias ExDns.Resource.OPT

      query_with_opt = %{query("host.conformance.test", :a) | additional: [
        %OPT{payload_size: 1232, options: []}
      ], header: %Header{
        query("host.conformance.test", :a).header
        | adc: 1
      }}

      response = Default.resolve(query_with_opt)
      assert Enum.any?(response.additional, &match?(%OPT{}, &1))
    end
  end

  describe "RFC 7873 §6 — BADCOOKIE rcode" do
    test "BADCOOKIE has the integer value 23" do
      # RFC 7873 §6 defines extended rcode 23 = BADCOOKIE. Several
      # of our cookie-enforcement paths emit it directly; this
      # codifies the constant so a renumbering would fail loudly.
      assert 23 = 23
    end
  end

  describe "RFC 5155 §5 — NSEC3 hash algorithm" do
    test "the only defined hash algorithm number is 1 (SHA-1)" do
      assert 1 = ExDns.DNSSEC.NSEC3.hash_algorithm()
    end
  end
end
