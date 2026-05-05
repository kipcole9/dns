defmodule ExDns.ExtendedDNSErrorsTest do
  @moduledoc """
  Verifies the RFC 8914 EDE codec: round-trips through encode +
  decode, atom + integer info-code surfaces, multi-EDE
  responses (RFC 8914 §3).
  """

  use ExUnit.Case, async: true

  alias ExDns.ExtendedDNSErrors, as: EDE

  doctest EDE

  describe "encode_option/2" do
    test "encodes a named atom + extra text" do
      {15, payload} = EDE.encode_option(:dnssec_bogus, "RRSIG over A doesn't verify")
      assert <<0, 6, "RRSIG over A doesn't verify">> = payload
    end

    test "encodes an integer info code" do
      assert {15, <<0, 99, "x">>} = EDE.encode_option(99, "x")
    end

    test "extra text defaults to empty" do
      assert {15, <<0, 0>>} = EDE.encode_option(:other)
    end

    test "raises on an unknown atom" do
      assert_raise ArgumentError, fn ->
        EDE.encode_option(:totally_made_up_code, "")
      end
    end
  end

  describe "decode_payload/1" do
    test "decodes a known info code into its atom" do
      assert {:dnssec_bogus, "boom"} = EDE.decode_payload(<<0, 6, "boom">>)
    end

    test "unknown info codes round-trip as integers" do
      assert {99, "weird"} = EDE.decode_payload(<<0, 99, "weird">>)
    end

    test "empty extra-text decodes cleanly" do
      assert {:other, ""} = EDE.decode_payload(<<0, 0>>)
    end

    test "malformed payloads degrade gracefully" do
      assert {:other, ""} = EDE.decode_payload(<<>>)
    end
  end

  describe "encode + decode round-trip" do
    test "every named atom round-trips" do
      atoms = [
        :other,
        :unsupported_dnskey_algorithm,
        :unsupported_ds_digest,
        :stale_answer,
        :forged_answer,
        :dnssec_indeterminate,
        :dnssec_bogus,
        :signature_expired,
        :signature_not_yet_valid,
        :dnskey_missing,
        :rrsigs_missing,
        :no_zone_key_bit_set,
        :nsec_missing,
        :cached_error,
        :not_ready,
        :blocked,
        :censored,
        :filtered,
        :prohibited,
        :stale_nxdomain_answer,
        :not_authoritative,
        :not_supported,
        :no_reachable_authority,
        :network_error,
        :invalid_data,
        :signature_expired_before_valid,
        :too_early,
        :unsupported_nsec3_iterations_value,
        :unable_to_conform_to_policy,
        :synthesized
      ]

      for atom <- atoms do
        {15, payload} = EDE.encode_option(atom, "msg")
        assert {^atom, "msg"} = EDE.decode_payload(payload)
      end
    end
  end

  describe "find_in_options/1" do
    test "returns [] when no EDE is present" do
      assert [] = EDE.find_in_options([{10, "cookie"}])
    end

    test "returns every EDE — RFC 8914 §3 allows multiple" do
      options = [
        {10, "cookie"},
        {15, <<0, 6, "bogus signature">>},
        {15, <<0, 7, "expired">>},
        {12, <<>>}
      ]

      assert [
               {:dnssec_bogus, "bogus signature"},
               {:signature_expired, "expired"}
             ] = EDE.find_in_options(options)
    end
  end
end
