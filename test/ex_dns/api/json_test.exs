defmodule ExDns.API.JSONTest do
  @moduledoc """
  Verifies the per-resource JSON behaviour (`encode_rdata/1` +
  `decode_rdata/1`) and the dispatcher wrapper in
  `ExDns.API.JSON`.

  Each resource is tested with a representative round-trip:
  encode the struct, decode it back, assert equivalence on
  the rdata fields.
  """

  use ExUnit.Case, async: true

  alias ExDns.API.JSON, as: APIJSON

  alias ExDns.Resource.{
    A,
    AAAA,
    CAA,
    CNAME,
    DNSKEY,
    DS,
    HINFO,
    MX,
    NAPTR,
    NS,
    PTR,
    SOA,
    SRV,
    SSHFP,
    TLSA,
    TXT
  }

  describe "API.JSON.record/1 wrapper" do
    test "envelope shape: id, name, type, ttl, class, rdata" do
      r = %A{name: "host.example", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}
      json = APIJSON.record(r)

      assert is_binary(json["id"])
      assert "host.example" = json["name"]
      assert "A" = json["type"]
      assert 60 = json["ttl"]
      assert "IN" = json["class"]
      assert %{"ipv4" => "1.2.3.4"} = json["rdata"]
    end

    test "trailing dots are stripped from the owner name" do
      r = %A{name: "trailing.example.", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}
      assert "trailing.example" = APIJSON.record(r)["name"]
    end

    test "record_id is stable and changes when rdata changes" do
      r1 = %A{name: "host.test", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}
      r2 = %A{name: "host.test", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}
      r3 = %A{name: "host.test", ttl: 60, class: :in, ipv4: {1, 2, 3, 5}}

      assert APIJSON.record_id(r1) == APIJSON.record_id(r2)
      refute APIJSON.record_id(r1) == APIJSON.record_id(r3)
    end
  end

  describe "round-trips" do
    test "A" do
      assert {:ok, %A{ipv4: {192, 0, 2, 1}}} =
               A.decode_rdata(A.encode_rdata(%A{ipv4: {192, 0, 2, 1}}))
    end

    test "AAAA" do
      assert {:ok, %AAAA{ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}}} =
               AAAA.decode_rdata(
                 AAAA.encode_rdata(%AAAA{ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}})
               )
    end

    test "CNAME" do
      assert {:ok, %CNAME{server: "target.example"}} =
               CNAME.decode_rdata(CNAME.encode_rdata(%CNAME{server: "target.example."}))
    end

    test "NS" do
      assert {:ok, %NS{server: "ns1.example"}} =
               NS.decode_rdata(NS.encode_rdata(%NS{server: "ns1.example."}))
    end

    test "PTR" do
      assert {:ok, %PTR{pointer: "1.0.0.127.in-addr.arpa"}} =
               PTR.decode_rdata(PTR.encode_rdata(%PTR{pointer: "1.0.0.127.in-addr.arpa."}))
    end

    test "TXT" do
      assert {:ok, %TXT{strings: ["a", "b"]}} =
               TXT.decode_rdata(TXT.encode_rdata(%TXT{strings: ["a", "b"]}))
    end

    test "MX" do
      assert {:ok, %MX{priority: 10, server: "mail.example"}} =
               MX.decode_rdata(MX.encode_rdata(%MX{priority: 10, server: "mail.example."}))
    end

    test "SRV" do
      record = %SRV{priority: 10, weight: 5, port: 5060, target: "sip.example."}

      assert {:ok, %SRV{priority: 10, weight: 5, port: 5060, target: "sip.example"}} =
               SRV.decode_rdata(SRV.encode_rdata(record))
    end

    test "SOA" do
      record = %SOA{
        mname: "ns1.example.",
        email: "h.example.",
        serial: 1,
        refresh: 60,
        retry: 60,
        expire: 60,
        minimum: 60
      }

      json = SOA.encode_rdata(record)
      assert {:ok, decoded} = SOA.decode_rdata(json)
      assert decoded.serial == 1
      assert decoded.mname == "ns1.example"
      assert decoded.email == "h.example"
    end

    test "CAA" do
      assert {:ok, %CAA{flags: 0, tag: "issue", value: "letsencrypt.org"}} =
               CAA.decode_rdata(
                 CAA.encode_rdata(%CAA{flags: 0, tag: "issue", value: "letsencrypt.org"})
               )
    end

    test "HINFO" do
      assert {:ok, %HINFO{cpu: "RFC8482", os: ""}} =
               HINFO.decode_rdata(HINFO.encode_rdata(%HINFO{cpu: "RFC8482", os: ""}))
    end

    test "DNSKEY" do
      record = %DNSKEY{flags: 256, protocol: 3, algorithm: 13, public_key: <<1, 2, 3, 4, 5>>}
      assert {:ok, ^record} = DNSKEY.decode_rdata(DNSKEY.encode_rdata(record))
    end

    test "DS" do
      record = %DS{
        key_tag: 12345,
        algorithm: 13,
        digest_type: 2,
        digest: <<0xAA, 0xBB, 0xCC, 0xDD>>
      }

      assert {:ok, ^record} = DS.decode_rdata(DS.encode_rdata(record))
    end

    test "TLSA" do
      record = %TLSA{
        cert_usage: 3,
        selector: 1,
        matching_type: 1,
        cert_data: <<0xAA, 0xBB>>
      }

      assert {:ok, ^record} = TLSA.decode_rdata(TLSA.encode_rdata(record))
    end

    test "SSHFP" do
      record = %SSHFP{algorithm: 4, fp_type: 2, fingerprint: <<1, 2, 3, 4>>}
      assert {:ok, ^record} = SSHFP.decode_rdata(SSHFP.encode_rdata(record))
    end

    test "NAPTR" do
      record = %NAPTR{
        order: 10,
        preference: 100,
        flags: "U",
        services: "E2U+sip",
        regexp: "!^.*$!sip:user@example.com!",
        replacement: "."
      }

      assert {:ok, ^record} = NAPTR.decode_rdata(NAPTR.encode_rdata(record))
    end
  end

  describe "decode error shapes" do
    test "A: invalid IPv4 → :invalid_ipv4" do
      assert {:error, :invalid_ipv4} = A.decode_rdata(%{"ipv4" => "not.an.ip"})
    end

    test "A: missing ipv4 key → :missing_ipv4" do
      assert {:error, :missing_ipv4} = A.decode_rdata(%{})
    end

    test "MX: missing priority → :invalid_mx_rdata" do
      assert {:error, :invalid_mx_rdata} = MX.decode_rdata(%{"server" => "x.test"})
    end

    test "DNSKEY: bad base64 public_key → :invalid_public_key_base64" do
      assert {:error, :invalid_public_key_base64} =
               DNSKEY.decode_rdata(%{
                 "flags" => 256,
                 "protocol" => 3,
                 "algorithm" => 13,
                 "public_key" => "not_b64!@#$"
               })
    end
  end

  describe "encode-only resources" do
    test "RRSIG encodes (no decode_rdata callback exported)" do
      record = %ExDns.Resource.RRSIG{
        type_covered: :a,
        algorithm: 13,
        labels: 2,
        original_ttl: 60,
        signature_expiration: 1_700_000_000,
        signature_inception: 1_699_000_000,
        key_tag: 12345,
        signer: "example.test.",
        signature: <<1, 2, 3>>
      }

      json = ExDns.Resource.RRSIG.encode_rdata(record)
      assert json["type_covered"] == "A"
      assert json["signer"] == "example.test"
      refute function_exported?(ExDns.Resource.RRSIG, :decode_rdata, 1)
    end

    test "NSEC encode-only" do
      record = %ExDns.Resource.NSEC{
        next_domain: "next.example.",
        type_bit_maps: [:a, :rrsig]
      }

      json = ExDns.Resource.NSEC.encode_rdata(record)
      assert json["next_domain"] == "next.example"
      assert json["types"] == ["A", "RRSIG"]
      refute function_exported?(ExDns.Resource.NSEC, :decode_rdata, 1)
    end
  end
end
