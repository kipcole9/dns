defmodule ExDns.Recursor.FullChainValidationTest do
  @moduledoc """
  End-to-end DNSSEC validation across a synthetic three-level chain
  (root → tld → leaf). Every record (DNSKEYs, DSes, the leaf answer)
  is signed by the appropriate zone's KSK, the IANA trust anchors are
  overridden to point at the synthetic root KSK, and the recursor's
  cache is pre-seeded so `Iterator.resolve_validated/3` doesn't have
  to do real network I/O.

  Demonstrates that the validator can build a chain root-first by
  fetching DNSKEY + DS at each cut, and that the resulting chain
  drives `ExDns.DNSSEC.validate_chain/3` to a `:secure` verdict.
  """

  use ExUnit.Case, async: false

  alias ExDns.DNSSEC.{Signer, Validator}
  alias ExDns.Message
  alias ExDns.Recursor.{Cache, Iterator}
  alias ExDns.Resource.{A, DNSKEY, DS}

  setup do
    Cache.init()
    Cache.clear()
    previous_anchors = Application.get_env(:ex_dns, :root_trust_anchors)

    on_exit(fn ->
      Cache.clear()

      case previous_anchors do
        nil -> Application.delete_env(:ex_dns, :root_trust_anchors)
        v -> Application.put_env(:ex_dns, :root_trust_anchors, v)
      end
    end)

    :ok
  end

  defp make_keypair(zone) do
    {public, private} = :crypto.generate_key(:ecdh, :secp256r1)
    <<0x04, raw_pub::binary-size(64)>> = public

    dnskey = %DNSKEY{
      name: zone,
      ttl: 86_400,
      class: :in,
      flags: 257,
      protocol: 3,
      algorithm: 13,
      public_key: raw_pub
    }

    {dnskey, private}
  end

  defp build_ds(child_zone, %DNSKEY{} = dnskey) do
    owner_bytes = Message.encode_name(String.downcase(child_zone, :ascii))

    rdata =
      <<dnskey.flags::size(16), dnskey.protocol::size(8), dnskey.algorithm::size(8),
        dnskey.public_key::binary>>

    digest = :crypto.hash(:sha256, owner_bytes <> rdata)

    %DS{
      name: child_zone,
      ttl: 86_400,
      class: :in,
      key_tag: Validator.key_tag(dnskey),
      algorithm: 13,
      digest_type: 2,
      digest: digest
    }
  end

  test "full root → tld → leaf chain in cache produces :secure" do
    # Three zones with KSKs.
    {root_dnskey, root_priv} = make_keypair("")
    {tld_dnskey, tld_priv} = make_keypair("tld")
    {leaf_dnskey, leaf_priv} = make_keypair("leaf.tld")

    # Root anchor is the root DS (computed from root DNSKEY).
    root_ds = build_ds("", root_dnskey)
    Application.put_env(:ex_dns, :root_trust_anchors, [root_ds])

    # DS records sit in PARENT zones.
    tld_ds = build_ds("tld", tld_dnskey)
    leaf_ds = build_ds("leaf.tld", leaf_dnskey)

    # Each DNSKEY RRset is self-signed by the zone's own KSK.
    {:ok, root_dnskey_sig} =
      Signer.sign_rrset([root_dnskey], root_dnskey, root_priv, signer: "")

    {:ok, tld_dnskey_sig} =
      Signer.sign_rrset([tld_dnskey], tld_dnskey, tld_priv, signer: "tld")

    {:ok, leaf_dnskey_sig} =
      Signer.sign_rrset([leaf_dnskey], leaf_dnskey, leaf_priv, signer: "leaf.tld")

    # DS RRsets are signed by the PARENT's ZSK.
    {:ok, tld_ds_sig} =
      Signer.sign_rrset([tld_ds], root_dnskey, root_priv, signer: "")

    {:ok, leaf_ds_sig} =
      Signer.sign_rrset([leaf_ds], tld_dnskey, tld_priv, signer: "tld")

    # Leaf RRset.
    leaf_records = [
      %A{name: "host.leaf.tld", ttl: 60, class: :in, ipv4: {198, 51, 100, 7}}
    ]

    {:ok, leaf_rrsig} =
      Signer.sign_rrset(leaf_records, leaf_dnskey, leaf_priv, signer: "leaf.tld")

    # Seed the cache with everything the chain walker will look up.
    Cache.put("", :dnskey, [root_dnskey, root_dnskey_sig], 86_400)
    Cache.put("tld", :dnskey, [tld_dnskey, tld_dnskey_sig], 86_400)
    Cache.put("leaf.tld", :dnskey, [leaf_dnskey, leaf_dnskey_sig], 86_400)
    Cache.put("tld", :ds, [tld_ds, tld_ds_sig], 86_400)
    Cache.put("leaf.tld", :ds, [leaf_ds, leaf_ds_sig], 86_400)
    Cache.put("host.leaf.tld", :a, leaf_records ++ [leaf_rrsig], 60)

    assert {:ok, ^leaf_records, :secure} =
             Iterator.resolve_validated("host.leaf.tld", :a)
  end

  test ":bogus when the leaf RRSIG is forged" do
    {root_dnskey, root_priv} = make_keypair("")
    {leaf_dnskey, _leaf_priv} = make_keypair("leaf")
    {_other_dnskey, other_priv} = make_keypair("leaf")

    root_ds = build_ds("", root_dnskey)
    Application.put_env(:ex_dns, :root_trust_anchors, [root_ds])

    leaf_ds = build_ds("leaf", leaf_dnskey)

    {:ok, root_dnskey_sig} =
      Signer.sign_rrset([root_dnskey], root_dnskey, root_priv, signer: "")

    # Sign DS for leaf with the root's key.
    {:ok, leaf_ds_sig} =
      Signer.sign_rrset([leaf_ds], root_dnskey, root_priv, signer: "")

    # Self-sign leaf DNSKEY with the OTHER private key — DNSKEY
    # self-signature won't verify against any of leaf's published
    # DNSKEYs, so the leaf link is bogus.
    {:ok, leaf_dnskey_sig} =
      Signer.sign_rrset([leaf_dnskey], leaf_dnskey, other_priv, signer: "leaf")

    leaf_records = [%A{name: "host.leaf", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}]
    {:ok, leaf_rrsig} = Signer.sign_rrset(leaf_records, leaf_dnskey, other_priv, signer: "leaf")

    Cache.put("", :dnskey, [root_dnskey, root_dnskey_sig], 86_400)
    Cache.put("leaf", :dnskey, [leaf_dnskey, leaf_dnskey_sig], 86_400)
    Cache.put("leaf", :ds, [leaf_ds, leaf_ds_sig], 86_400)
    Cache.put("host.leaf", :a, leaf_records ++ [leaf_rrsig], 60)

    assert {:ok, _records, :bogus} =
             Iterator.resolve_validated("host.leaf", :a)
  end
end
