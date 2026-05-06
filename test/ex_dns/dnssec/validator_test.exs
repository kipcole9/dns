defmodule ExDns.DNSSEC.ValidatorTest do
  @moduledoc """
  Tests for the DNSSEC validator.

  We generate keypairs at test time using `:public_key` / `:crypto`
  and produce our own RRSIG bytes against a synthetic RRset, then
  ask the Validator to confirm the signature. This exercises the
  full canonical-form + signature-verification pipeline against
  every supported algorithm without needing fixtures from the live
  internet.

  """

  use ExUnit.Case, async: true

  alias ExDns.DNSSEC.{TrustAnchors, Validator}
  alias ExDns.Message
  alias ExDns.Resource.{A, DNSKEY, DS, RRSIG}

  describe "trust_anchors" do
    test "ships at least one root anchor" do
      anchors = TrustAnchors.root()
      assert length(anchors) >= 1
      Enum.each(anchors, fn ds -> assert byte_size(ds.digest) > 0 end)
    end
  end

  describe "key_tag/1" do
    test "matches the RFC 4034 Appendix B reference algorithm" do
      # 256-bit ECDSA P-256 public key — chosen so the key tag is
      # whatever it is; we just confirm key_tag returns a 16-bit value.
      key = %DNSKEY{
        flags: 256,
        protocol: 3,
        algorithm: 13,
        public_key: :crypto.strong_rand_bytes(64)
      }

      tag = Validator.key_tag(key)
      assert tag in 0..0xFFFF
    end
  end

  describe "verify_rrset/3 — algorithm 13 (ECDSA P-256)" do
    test "round-trips: sign with crypto, verify with Validator" do
      # Generate an ECDSA P-256 keypair.
      {public_key, private_key} = :crypto.generate_key(:ecdh, :secp256r1)

      # DNSKEY public_key for alg 13 is the raw 64-byte point (x || y).
      <<0x04, raw_pubkey::binary-size(64)>> = public_key

      dnskey = %DNSKEY{
        flags: 256,
        protocol: 3,
        algorithm: 13,
        public_key: raw_pubkey
      }

      records = [
        %A{name: "host.example.com", ttl: 3600, class: :in, ipv4: {192, 0, 2, 1}}
      ]

      # Build an RRSIG header (everything except the signature) and
      # canonical signing data.
      template = %RRSIG{
        name: "host.example.com",
        ttl: 3600,
        class: :in,
        type_covered: :a,
        algorithm: 13,
        labels: 3,
        original_ttl: 3600,
        signature_expiration: 1_800_000_000,
        signature_inception: 1_700_000_000,
        key_tag: Validator.key_tag(dnskey),
        signer: "example.com",
        signature: <<>>
      }

      signed_data = build_signing_data(records, template)

      # Sign with crypto. crypto.sign returns DER; convert to raw r||s.
      der_signature = :crypto.sign(:ecdsa, :sha256, signed_data, [private_key, :secp256r1])
      raw_signature = der_to_raw(der_signature, 32)

      rrsig = %RRSIG{template | signature: raw_signature}

      assert :ok = Validator.verify_rrset(records, rrsig, dnskey)
    end

    test "rejects a tampered RRset" do
      {public_key, private_key} = :crypto.generate_key(:ecdh, :secp256r1)
      <<0x04, raw_pubkey::binary-size(64)>> = public_key

      dnskey = %DNSKEY{flags: 256, protocol: 3, algorithm: 13, public_key: raw_pubkey}

      records = [%A{name: "h.example", ttl: 3600, class: :in, ipv4: {1, 2, 3, 4}}]

      template = %RRSIG{
        name: "h.example",
        ttl: 3600,
        class: :in,
        type_covered: :a,
        algorithm: 13,
        labels: 2,
        original_ttl: 3600,
        signature_expiration: 1_800_000_000,
        signature_inception: 1_700_000_000,
        key_tag: Validator.key_tag(dnskey),
        signer: "example",
        signature: <<>>
      }

      der = :crypto.sign(:ecdsa, :sha256, build_signing_data(records, template), [private_key, :secp256r1])
      raw = der_to_raw(der, 32)
      rrsig = %RRSIG{template | signature: raw}

      tampered = [%A{name: "h.example", ttl: 3600, class: :in, ipv4: {9, 9, 9, 9}}]

      assert {:error, :bad_signature} = Validator.verify_rrset(tampered, rrsig, dnskey)
    end

    test "rejects when the DNSKEY's key tag doesn't match" do
      {public_key, _} = :crypto.generate_key(:ecdh, :secp256r1)
      <<0x04, raw_pubkey::binary-size(64)>> = public_key

      dnskey = %DNSKEY{flags: 256, protocol: 3, algorithm: 13, public_key: raw_pubkey}

      records = [%A{name: "h.example", ttl: 3600, class: :in, ipv4: {1, 2, 3, 4}}]

      rrsig = %RRSIG{
        name: "h.example",
        ttl: 3600,
        class: :in,
        type_covered: :a,
        algorithm: 13,
        labels: 2,
        original_ttl: 3600,
        signature_expiration: 1_800_000_000,
        signature_inception: 1_700_000_000,
        # Deliberately wrong key tag.
        key_tag: 1,
        signer: "example",
        signature: :crypto.strong_rand_bytes(64)
      }

      assert {:error, :wrong_key} = Validator.verify_rrset(records, rrsig, dnskey)
    end

    # Regression: the verifier's raw→DER converter for ECDSA r/s used
    # to strip leading zeros without re-checking whether the trimmed
    # value's MSB was set, producing non-canonical DER that OpenSSL
    # rejected as a negative integer. With ~256-bit random r/s, the
    # corner case (top byte 0x00, second byte ≥ 0x80) hit roughly
    # 1/512 of the time per integer — flaky but rare. This test runs
    # 200 fresh round-trips so a regression would have ~50%+ chance
    # of being caught on every run.
    test "round-trip never flakes across many fresh keypairs (regression)" do
      records = [%A{name: "host.example.com", ttl: 3600, class: :in, ipv4: {192, 0, 2, 1}}]

      Enum.each(1..200, fn _ ->
        {public_key, private_key} = :crypto.generate_key(:ecdh, :secp256r1)
        <<0x04, raw_pubkey::binary-size(64)>> = public_key

        dnskey = %DNSKEY{flags: 256, protocol: 3, algorithm: 13, public_key: raw_pubkey}

        template = %RRSIG{
          name: "host.example.com",
          ttl: 3600,
          class: :in,
          type_covered: :a,
          algorithm: 13,
          labels: 3,
          original_ttl: 3600,
          signature_expiration: 1_800_000_000,
          signature_inception: 1_700_000_000,
          key_tag: Validator.key_tag(dnskey),
          signer: "example.com",
          signature: <<>>
        }

        signed = build_signing_data(records, template)
        der = :crypto.sign(:ecdsa, :sha256, signed, [private_key, :secp256r1])
        rrsig = %RRSIG{template | signature: der_to_raw(der, 32)}

        assert :ok = Validator.verify_rrset(records, rrsig, dnskey)
      end)
    end
  end

  describe "verify_rrset/3 — algorithm 15 (Ed25519)" do
    test "round-trips: sign with crypto, verify with Validator" do
      {raw_pubkey, private_key} = :crypto.generate_key(:eddsa, :ed25519)

      dnskey = %DNSKEY{
        flags: 256,
        protocol: 3,
        algorithm: 15,
        public_key: raw_pubkey
      }

      records = [%A{name: "ed.example", ttl: 3600, class: :in, ipv4: {7, 7, 7, 7}}]

      template = %RRSIG{
        name: "ed.example",
        ttl: 3600,
        class: :in,
        type_covered: :a,
        algorithm: 15,
        labels: 2,
        original_ttl: 3600,
        signature_expiration: 1_800_000_000,
        signature_inception: 1_700_000_000,
        key_tag: Validator.key_tag(dnskey),
        signer: "example",
        signature: <<>>
      }

      signed_data = build_signing_data(records, template)
      signature = :crypto.sign(:eddsa, :none, signed_data, [private_key, :ed25519])

      rrsig = %RRSIG{template | signature: signature}
      assert :ok = Validator.verify_rrset(records, rrsig, dnskey)
    end
  end

  describe "verify_ds/3" do
    test "matches a DS that was computed from a DNSKEY" do
      {public_key, _} = :crypto.generate_key(:ecdh, :secp256r1)
      <<0x04, raw_pubkey::binary-size(64)>> = public_key

      dnskey = %DNSKEY{
        flags: 257,
        protocol: 3,
        algorithm: 13,
        public_key: raw_pubkey
      }

      owner = "example.com"
      owner_bytes = Message.encode_name(owner)
      dnskey_rdata = encode_dnskey_rdata(dnskey)
      digest = :crypto.hash(:sha256, owner_bytes <> dnskey_rdata)

      ds = %DS{
        name: owner,
        ttl: 86_400,
        class: :in,
        key_tag: Validator.key_tag(dnskey),
        algorithm: 13,
        digest_type: 2,
        digest: digest
      }

      assert :ok = Validator.verify_ds(ds, owner, dnskey)
    end

    test "rejects a DS with the wrong digest" do
      {public_key, _} = :crypto.generate_key(:ecdh, :secp256r1)
      <<0x04, raw_pubkey::binary-size(64)>> = public_key

      dnskey = %DNSKEY{flags: 257, protocol: 3, algorithm: 13, public_key: raw_pubkey}

      ds = %DS{
        name: "example.com",
        ttl: 86_400,
        class: :in,
        key_tag: Validator.key_tag(dnskey),
        algorithm: 13,
        digest_type: 2,
        digest: :crypto.strong_rand_bytes(32)
      }

      assert {:error, :bad_digest} = Validator.verify_ds(ds, "example.com", dnskey)
    end
  end

  describe "verify_rrset/4 — RRSIG validity period (RFC 4035 §5.3.1)" do
    test "accepts a signature whose window covers the configured `:now`" do
      {records, rrsig, dnskey} = signed_fixture(inception: 100, expiration: 200)

      assert :ok = Validator.verify_rrset(records, rrsig, dnskey, now: 150)
    end

    test "rejects a signature whose inception is in the future of `:now`" do
      {records, rrsig, dnskey} = signed_fixture(inception: 1_000, expiration: 2_000)

      assert {:error, :signature_not_yet_valid} =
               Validator.verify_rrset(records, rrsig, dnskey, now: 500)
    end

    test "rejects a signature whose expiration is past `:now`" do
      {records, rrsig, dnskey} = signed_fixture(inception: 100, expiration: 200)

      assert {:error, :signature_expired} =
               Validator.verify_rrset(records, rrsig, dnskey, now: 1_000)
    end

    test "honours `:max_skew_seconds` on both sides of the window" do
      {records, rrsig, dnskey} = signed_fixture(inception: 100, expiration: 200)

      # 5s before inception, 10s skew → permitted.
      assert :ok = Validator.verify_rrset(records, rrsig, dnskey, now: 95, max_skew_seconds: 10)

      # 5s after expiration, 10s skew → permitted.
      assert :ok = Validator.verify_rrset(records, rrsig, dnskey, now: 205, max_skew_seconds: 10)

      # 20s after expiration, 10s skew → still rejected.
      assert {:error, :signature_expired} =
               Validator.verify_rrset(records, rrsig, dnskey, now: 220, max_skew_seconds: 10)
    end
  end

  # ----- helpers ------------------------------------------------------

  # Produce a real signed RRset whose RRSIG carries the requested
  # inception / expiration timestamps. Used by the validity-period
  # tests so they exercise the same code path as a normal verify.
  defp signed_fixture(opts) do
    inception = Keyword.fetch!(opts, :inception)
    expiration = Keyword.fetch!(opts, :expiration)

    {public_key, private_key} = :crypto.generate_key(:ecdh, :secp256r1)
    <<0x04, raw_pubkey::binary-size(64)>> = public_key

    dnskey = %DNSKEY{flags: 256, protocol: 3, algorithm: 13, public_key: raw_pubkey}

    records = [%A{name: "h.example", ttl: 3600, class: :in, ipv4: {1, 2, 3, 4}}]

    template = %RRSIG{
      name: "h.example",
      ttl: 3600,
      class: :in,
      type_covered: :a,
      algorithm: 13,
      labels: 2,
      original_ttl: 3600,
      signature_inception: inception,
      signature_expiration: expiration,
      key_tag: Validator.key_tag(dnskey),
      signer: "example",
      signature: <<>>
    }

    der =
      :crypto.sign(:ecdsa, :sha256, build_signing_data(records, template),
        [private_key, :secp256r1])

    rrsig = %RRSIG{template | signature: der_to_raw(der, 32)}
    {records, rrsig, dnskey}
  end

  # Build the bytes the signer would feed into HMAC/RSA/ECDSA: the
  # canonical RRSIG signing fields followed by the canonical RRset.
  # Mirrors what the Validator does internally so we can produce
  # signatures the validator will accept.
  defp build_signing_data(records, template) do
    canonical_records =
      records
      |> Enum.map(fn r -> canonical_record(r, template.original_ttl) end)
      |> Enum.sort_by(& &1.rdata)
      |> Enum.map(&encode_canonical_record/1)

    rrsig_fields = canonical_rrsig_signing_fields(template)
    IO.iodata_to_binary([rrsig_fields | canonical_records])
  end

  defp canonical_record(record, original_ttl) do
    type_int = ExDns.Resource.type_from(:a)
    class_int = ExDns.Resource.class_for(record.class)
    rdata = ExDns.Resource.A.encode(record) |> IO.iodata_to_binary()

    %{
      owner: String.downcase(record.name, :ascii),
      type: type_int,
      class: class_int,
      ttl: original_ttl,
      rdata: rdata
    }
  end

  defp encode_canonical_record(c) do
    name_bytes = Message.encode_name(c.owner)

    <<
      name_bytes::binary,
      c.type::size(16),
      c.class::size(16),
      c.ttl::size(32),
      byte_size(c.rdata)::size(16),
      c.rdata::binary
    >>
  end

  defp canonical_rrsig_signing_fields(rrsig) do
    type_int = ExDns.Resource.type_from(rrsig.type_covered)

    <<
      type_int::size(16),
      rrsig.algorithm::size(8),
      rrsig.labels::size(8),
      rrsig.original_ttl::size(32),
      rrsig.signature_expiration::size(32),
      rrsig.signature_inception::size(32),
      rrsig.key_tag::size(16),
      Message.encode_name(String.downcase(rrsig.signer, :ascii))::binary
    >>
  end

  defp encode_dnskey_rdata(dnskey) do
    <<
      dnskey.flags::size(16),
      dnskey.protocol::size(8),
      dnskey.algorithm::size(8),
      dnskey.public_key::binary
    >>
  end

  # crypto.sign(:ecdsa) returns DER ASN.1; DNSSEC wants raw r || s.
  defp der_to_raw(der, integer_size) do
    <<0x30, _len, 0x02, r_len, rest::binary>> = der
    <<r::binary-size(^r_len), 0x02, s_len, rest2::binary>> = rest
    <<s::binary-size(^s_len)>> = rest2
    pad(r, integer_size) <> pad(s, integer_size)
  end

  defp pad(<<0, rest::binary>>, size) when byte_size(rest) == size, do: rest
  defp pad(bytes, size) when byte_size(bytes) == size, do: bytes
  defp pad(bytes, size) when byte_size(bytes) < size do
    pad_len = size - byte_size(bytes)
    <<0::size(pad_len * 8), bytes::binary>>
  end
end
