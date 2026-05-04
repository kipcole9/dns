defmodule ExDns.DNSSEC.SignerTest do
  use ExUnit.Case, async: true

  alias ExDns.DNSSEC.{Signer, Validator}
  alias ExDns.Resource.{A, DNSKEY}

  describe "sign_rrset/4 round-trips with Validator.verify_rrset/3" do
    test "signs an A RRset with ECDSA P-256, verifies with the matching DNSKEY" do
      {public, private} = :crypto.generate_key(:ecdh, :secp256r1)
      <<0x04, raw_pub::binary-size(64)>> = public

      dnskey = %DNSKEY{
        name: "example.com",
        ttl: 86_400,
        class: :in,
        flags: 257,
        protocol: 3,
        algorithm: 13,
        public_key: raw_pub
      }

      records = [
        %A{name: "host.example.com", ttl: 3600, class: :in, ipv4: {192, 0, 2, 1}}
      ]

      assert {:ok, rrsig} =
               Signer.sign_rrset(records, dnskey, private,
                 signer: "example.com",
                 inception: 1_700_000_000,
                 expiration: 1_900_000_000
               )

      assert rrsig.algorithm == 13
      assert rrsig.signer == "example.com"
      assert rrsig.type_covered == :a

      assert :ok = Validator.verify_rrset(records, rrsig, dnskey)
    end

    test "signs a multi-record RRset (RRsets are sorted canonically)" do
      {public, private} = :crypto.generate_key(:ecdh, :secp256r1)
      <<0x04, raw_pub::binary-size(64)>> = public

      dnskey = %DNSKEY{
        name: "example.com",
        ttl: 86_400,
        class: :in,
        flags: 257,
        protocol: 3,
        algorithm: 13,
        public_key: raw_pub
      }

      records = [
        %A{name: "host.example.com", ttl: 3600, class: :in, ipv4: {192, 0, 2, 9}},
        %A{name: "host.example.com", ttl: 3600, class: :in, ipv4: {192, 0, 2, 1}},
        %A{name: "host.example.com", ttl: 3600, class: :in, ipv4: {192, 0, 2, 5}}
      ]

      {:ok, rrsig} = Signer.sign_rrset(records, dnskey, private, signer: "example.com")

      assert :ok = Validator.verify_rrset(records, rrsig, dnskey)
    end

    test "signs with Ed25519 (algorithm 15)" do
      {raw_pub, private} = :crypto.generate_key(:eddsa, :ed25519)

      dnskey = %DNSKEY{
        name: "ed.example",
        ttl: 86_400,
        class: :in,
        flags: 257,
        protocol: 3,
        algorithm: 15,
        public_key: raw_pub
      }

      records = [%A{name: "h.ed.example", ttl: 60, class: :in, ipv4: {7, 7, 7, 7}}]

      {:ok, rrsig} = Signer.sign_rrset(records, dnskey, private, signer: "ed.example")
      assert :ok = Validator.verify_rrset(records, rrsig, dnskey)
    end

    test "signs with RSA-SHA256 (algorithm 8)" do
      # 2048-bit RSA key. :crypto.generate_key returns {pub, priv}
      # where pub is [exp, modulus] and priv is the list form
      # :crypto.sign expects.
      {[exponent, modulus], priv} = :crypto.generate_key(:rsa, {2048, 65_537})

      raw_pub = encode_rsa_public_key(exponent, modulus)

      dnskey = %DNSKEY{
        name: "rsa.example",
        ttl: 86_400,
        class: :in,
        flags: 257,
        protocol: 3,
        algorithm: 8,
        public_key: raw_pub
      }

      records = [%A{name: "h.rsa.example", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}]

      {:ok, rrsig} = Signer.sign_rrset(records, dnskey, priv, signer: "rsa.example")
      assert :ok = Validator.verify_rrset(records, rrsig, dnskey)
    end
  end

  defp encode_rsa_public_key(exp, mod) do
    exp_bytes = to_unsigned(exp)
    mod_bytes = to_unsigned(mod)

    if byte_size(exp_bytes) <= 255 do
      <<byte_size(exp_bytes)::size(8), exp_bytes::binary, mod_bytes::binary>>
    else
      <<0::size(8), byte_size(exp_bytes)::size(16), exp_bytes::binary, mod_bytes::binary>>
    end
  end

  defp to_unsigned(int) when is_integer(int), do: :binary.encode_unsigned(int)
  defp to_unsigned(bin) when is_binary(bin), do: bin
end
