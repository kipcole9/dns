defmodule ExDns.DNSSEC.KSKRolloverTest do
  @moduledoc """
  Verifies the KSK rollover phases plus CDS/CDNSKEY publication
  per RFC 7344 / RFC 8078.
  """

  use ExUnit.Case, async: false

  alias ExDns.DNSSEC.{KeyStore, Rollover, Validator}
  alias ExDns.Message
  alias ExDns.Resource.{CDNSKEY, CDS, DNSKEY}

  setup do
    KeyStore.init()
    KeyStore.clear()
    on_exit(fn -> KeyStore.clear() end)
    :ok
  end

  describe "prepare_ksk_rollover/2" do
    test "stages a new key with KSK flags (257)" do
      assert {:ok, %DNSKEY{flags: 257}, _key_tag} =
               Rollover.prepare_ksk_rollover("example.test")
    end

    test "respects an explicit :flags override" do
      assert {:ok, %DNSKEY{flags: 257}, _} =
               Rollover.prepare_ksk_rollover("example.test", flags: 257)
    end

    test "stores the new key in :incoming state" do
      {:ok, _, key_tag} = Rollover.prepare_ksk_rollover("example.test")
      [entry] = KeyStore.keys_for_zone("example.test")
      assert entry.state == :incoming
      assert Validator.key_tag(entry.dnskey) == key_tag
    end
  end

  describe "complete_ksk_rollover/2" do
    test "promotes the new KSK + retires any previously active KSKs" do
      {:ok, _, old_ksk_tag} = Rollover.prepare_ksk_rollover("example.test")
      :ok = KeyStore.activate_key("example.test", old_ksk_tag)

      {:ok, _, new_ksk_tag} = Rollover.prepare_ksk_rollover("example.test")
      :ok = Rollover.complete_ksk_rollover("example.test", new_ksk_tag)

      states =
        for entry <- KeyStore.keys_for_zone("example.test"),
            into: %{} do
          {Validator.key_tag(entry.dnskey), entry.state}
        end

      assert states[new_ksk_tag] == :active
      assert states[old_ksk_tag] == :retired
    end

    test "does NOT touch active ZSKs (flags=256)" do
      {:ok, _, zsk_tag} = Rollover.prepare_zsk_rollover("example.test")
      :ok = KeyStore.activate_key("example.test", zsk_tag)

      {:ok, _, ksk_tag} = Rollover.prepare_ksk_rollover("example.test")
      :ok = Rollover.complete_ksk_rollover("example.test", ksk_tag)

      states =
        for entry <- KeyStore.keys_for_zone("example.test"),
            into: %{} do
          {Validator.key_tag(entry.dnskey), entry.state}
        end

      # ZSK should still be active.
      assert states[zsk_tag] == :active
      assert states[ksk_tag] == :active
    end
  end

  describe "cds_records_for/2" do
    test "returns one CDS per active KSK with SHA-256 digest by default" do
      {:ok, dnskey, ksk_tag} = Rollover.prepare_ksk_rollover("example.test")
      :ok = KeyStore.activate_key("example.test", ksk_tag)

      [cds] = Rollover.cds_records_for("example.test")
      assert %CDS{} = cds
      assert cds.key_tag == ksk_tag
      assert cds.algorithm == 13
      # SHA-256 digest is 32 bytes.
      assert cds.digest_type == 2
      assert byte_size(cds.digest) == 32

      # Verify the digest matches the canonical RFC 4034 §5.1.4
      # computation.
      owner = Message.encode_name("example.test")

      rdata =
        <<dnskey.flags::size(16), dnskey.protocol::size(8), dnskey.algorithm::size(8),
          dnskey.public_key::binary>>

      assert cds.digest == :crypto.hash(:sha256, owner <> rdata)
    end

    test "honours :digest_type option for SHA-1 (digest type 1)" do
      {:ok, _, ksk_tag} = Rollover.prepare_ksk_rollover("example.test")
      :ok = KeyStore.activate_key("example.test", ksk_tag)

      [cds] = Rollover.cds_records_for("example.test", digest_type: 1)
      # SHA-1 digest is 20 bytes.
      assert cds.digest_type == 1
      assert byte_size(cds.digest) == 20
    end

    test "returns [] when no active KSKs" do
      assert [] = Rollover.cds_records_for("example.test")
    end

    test "ignores ZSKs even if active" do
      {:ok, _, zsk_tag} = Rollover.prepare_zsk_rollover("example.test")
      :ok = KeyStore.activate_key("example.test", zsk_tag)

      assert [] = Rollover.cds_records_for("example.test")
    end

    test "produces multiple records during rollover overlap" do
      {:ok, _, ksk1} = Rollover.prepare_ksk_rollover("example.test")
      :ok = KeyStore.activate_key("example.test", ksk1)
      {:ok, _, ksk2} = Rollover.prepare_ksk_rollover("example.test")
      :ok = KeyStore.activate_key("example.test", ksk2)

      cds_list = Rollover.cds_records_for("example.test")
      tags = Enum.map(cds_list, & &1.key_tag)

      assert ksk1 in tags
      assert ksk2 in tags
    end
  end

  describe "cdnskey_records_for/2" do
    test "echoes the active KSK's DNSKEY fields" do
      {:ok, dnskey, ksk_tag} = Rollover.prepare_ksk_rollover("example.test")
      :ok = KeyStore.activate_key("example.test", ksk_tag)

      [cdnskey] = Rollover.cdnskey_records_for("example.test")
      assert %CDNSKEY{} = cdnskey
      assert cdnskey.flags == 257
      assert cdnskey.protocol == 3
      assert cdnskey.algorithm == 13
      assert cdnskey.public_key == dnskey.public_key
    end

    test "returns [] when no active KSKs" do
      assert [] = Rollover.cdnskey_records_for("example.test")
    end
  end

  describe "RFC 8078 §4 delete records" do
    test "CDS.delete_record/1 produces the sentinel record" do
      record = ExDns.Resource.CDS.delete_record("example.test")
      assert record.key_tag == 0
      assert record.algorithm == 0
      assert record.digest_type == 0
      assert record.digest == <<0>>
    end

    test "CDNSKEY.delete_record/1 produces the sentinel record" do
      record = ExDns.Resource.CDNSKEY.delete_record("example.test")
      assert record.flags == 0
      assert record.protocol == 3
      assert record.algorithm == 0
      assert record.public_key == <<0>>
    end
  end
end
