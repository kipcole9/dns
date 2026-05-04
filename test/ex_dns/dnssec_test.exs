defmodule ExDns.DNSSECTest do
  @moduledoc """
  End-to-end DNSSEC chain validation test.

  Builds a synthetic chain from a root we control (overriding the IANA
  trust anchors via `Application.put_env(:ex_dns, :root_trust_anchors, ...)`)
  down through one TLD level to a leaf zone, signs a leaf RRset, and
  asks `ExDns.DNSSEC.validate_chain/3` to verify.

  Demonstrates that the validator + chain composition correctly handles
  multi-level DNSSEC trust paths.

  """

  use ExUnit.Case, async: false

  alias ExDns.DNSSEC
  alias ExDns.DNSSEC.Validator
  alias ExDns.Message
  alias ExDns.Resource.{A, DNSKEY, DS, RRSIG}

  setup do
    previous = Application.get_env(:ex_dns, :root_trust_anchors)
    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :root_trust_anchors)
        value -> Application.put_env(:ex_dns, :root_trust_anchors, value)
      end
    end)

    :ok
  end

  describe "validate_chain/3 — full root → tld → leaf path" do
    test "accepts a properly-signed chain" do
      # Three zones: root, tld, leaf
      {root_pub, root_priv} = make_keypair()
      {tld_pub, tld_priv} = make_keypair()
      {leaf_pub, leaf_priv} = make_keypair()

      root_dnskey = make_dnskey(root_pub, 257)
      tld_dnskey = make_dnskey(tld_pub, 257)
      leaf_dnskey = make_dnskey(leaf_pub, 257)

      # Override IANA trust anchors with our root's DS.
      root_ds = build_ds("", root_dnskey)
      Application.put_env(:ex_dns, :root_trust_anchors, [root_ds])

      # Each link's DNSKEY RRset is self-signed by one of its keys.
      root_dnskey_sig =
        sign_rrset([root_dnskey], "", :dnskey, root_priv, root_dnskey, "")

      # Root signs the TLD's DS record.
      tld_ds = build_ds("tld", tld_dnskey)

      # Skipping intermediate DS-RRSIG validation in the chain
      # composition for this first cut: the chain validator focuses on
      # DNSKEY-against-DS bridges and the leaf signature; it accepts
      # the parent's DS as a given (the iterator that builds the
      # chain is responsible for fetching+validating those).

      tld_dnskey_sig =
        sign_rrset([tld_dnskey], "tld", :dnskey, tld_priv, tld_dnskey, "tld")

      # TLD signs leaf's DS record.
      leaf_ds = build_ds("leaf.tld", leaf_dnskey)

      leaf_dnskey_sig =
        sign_rrset([leaf_dnskey], "leaf.tld", :dnskey, leaf_priv, leaf_dnskey, "leaf.tld")

      # Build the chain.
      chain = [
        %{
          zone: "",
          dnskeys: [root_dnskey],
          dnskey_rrsig: root_dnskey_sig,
          parent_ds: :root_anchor
        },
        %{
          zone: "tld",
          dnskeys: [tld_dnskey],
          dnskey_rrsig: tld_dnskey_sig,
          parent_ds: [tld_ds]
        },
        %{
          zone: "leaf.tld",
          dnskeys: [leaf_dnskey],
          dnskey_rrsig: leaf_dnskey_sig,
          parent_ds: [leaf_ds]
        }
      ]

      # Leaf signs its own A record.
      records = [%A{name: "host.leaf.tld", ttl: 3600, class: :in, ipv4: {198, 51, 100, 1}}]
      rrsig = sign_rrset(records, "host.leaf.tld", :a, leaf_priv, leaf_dnskey, "leaf.tld")

      assert {:secure, ^records} = DNSSEC.validate_chain(records, rrsig, chain)
    end

    test "rejects a chain where the leaf signature is bogus" do
      {root_pub, root_priv} = make_keypair()
      {leaf_pub, _leaf_priv} = make_keypair()

      root_dnskey = make_dnskey(root_pub, 257)
      leaf_dnskey = make_dnskey(leaf_pub, 257)

      root_ds = build_ds("", root_dnskey)
      Application.put_env(:ex_dns, :root_trust_anchors, [root_ds])

      root_dnskey_sig = sign_rrset([root_dnskey], "", :dnskey, root_priv, root_dnskey, "")
      leaf_ds = build_ds("leaf.tld", leaf_dnskey)

      # Self-sign leaf DNSKEY with a DIFFERENT key — the leaf.tld DNSKEY
      # RRset will fail to validate.
      {_other_pub, other_priv} = make_keypair()
      leaf_dnskey_sig = sign_rrset([leaf_dnskey], "leaf.tld", :dnskey, other_priv, leaf_dnskey, "leaf.tld")

      chain = [
        %{
          zone: "",
          dnskeys: [root_dnskey],
          dnskey_rrsig: root_dnskey_sig,
          parent_ds: :root_anchor
        },
        %{
          zone: "leaf.tld",
          dnskeys: [leaf_dnskey],
          dnskey_rrsig: leaf_dnskey_sig,
          parent_ds: [leaf_ds]
        }
      ]

      records = [%A{name: "host.leaf.tld", ttl: 3600, class: :in, ipv4: {198, 51, 100, 1}}]
      rrsig = sign_rrset(records, "host.leaf.tld", :a, other_priv, leaf_dnskey, "leaf.tld")

      assert {:bogus, _} = DNSSEC.validate_chain(records, rrsig, chain)
    end

    test "indeterminate when the chain is empty" do
      records = [%A{name: "x.example", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}]

      rrsig = %RRSIG{
        name: "x.example",
        ttl: 60,
        class: :in,
        type_covered: :a,
        algorithm: 13,
        labels: 2,
        original_ttl: 60,
        signature_expiration: 1_800_000_000,
        signature_inception: 1_700_000_000,
        key_tag: 0,
        signer: "example",
        signature: <<>>
      }

      assert {:indeterminate, :empty_chain} = DNSSEC.validate_chain(records, rrsig, [])
    end
  end

  # ----- helpers ------------------------------------------------------

  defp make_keypair do
    {public, private} = :crypto.generate_key(:ecdh, :secp256r1)
    <<0x04, raw_pub::binary-size(64)>> = public
    {raw_pub, private}
  end

  defp make_dnskey(raw_pub, flags) do
    %DNSKEY{
      name: "",
      ttl: 86_400,
      class: :in,
      flags: flags,
      protocol: 3,
      algorithm: 13,
      public_key: raw_pub
    }
  end

  defp build_ds(owner, %DNSKEY{} = dnskey) do
    owner_bytes = Message.encode_name(String.downcase(owner, :ascii))
    rdata = encode_dnskey_rdata(dnskey)
    digest = :crypto.hash(:sha256, owner_bytes <> rdata)

    %DS{
      name: owner,
      ttl: 86_400,
      class: :in,
      key_tag: Validator.key_tag(dnskey),
      algorithm: 13,
      digest_type: 2,
      digest: digest
    }
  end

  defp encode_dnskey_rdata(%DNSKEY{} = d) do
    <<d.flags::size(16), d.protocol::size(8), d.algorithm::size(8), d.public_key::binary>>
  end

  defp sign_rrset(records, owner, type, private_key, dnskey, signer) do
    template = %RRSIG{
      name: owner,
      ttl: 3600,
      class: :in,
      type_covered: type,
      algorithm: 13,
      labels: owner |> String.split(".", trim: true) |> length(),
      original_ttl: hd(records).ttl,
      signature_expiration: 1_900_000_000,
      signature_inception: 1_700_000_000,
      key_tag: Validator.key_tag(dnskey),
      signer: signer,
      signature: <<>>
    }

    signed_data = build_signing_data(records, template, type)
    der = :crypto.sign(:ecdsa, :sha256, signed_data, [private_key, :secp256r1])
    raw = der_to_raw(der, 32)
    %RRSIG{template | signature: raw}
  end

  defp build_signing_data(records, template, type) do
    canonical_records =
      records
      |> Enum.map(fn r -> canonical_record(r, template.original_ttl, type) end)
      |> Enum.sort_by(& &1.rdata)
      |> Enum.map(&encode_canonical_record/1)

    rrsig_fields = canonical_rrsig_signing_fields(template)
    IO.iodata_to_binary([rrsig_fields | canonical_records])
  end

  defp canonical_record(record, original_ttl, type) do
    type_int = ExDns.Resource.type_from(type)
    class_int = ExDns.Resource.class_for(record.class)

    rdata =
      case type do
        :a -> ExDns.Resource.A.encode(record) |> IO.iodata_to_binary()
        :dnskey -> encode_dnskey_rdata(record)
      end

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
