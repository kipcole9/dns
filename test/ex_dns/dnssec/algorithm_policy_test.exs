defmodule ExDns.DNSSEC.AlgorithmPolicyTest do
  @moduledoc """
  Verifies the RFC 8624 algorithm-policy gate is wired into the
  signer, validator, key generator, and exposes correct status
  classifications.
  """

  use ExUnit.Case, async: false

  alias ExDns.DNSSEC.{AlgorithmPolicy, Rollover, Signer, Validator}
  alias ExDns.Resource.{A, DNSKEY, RRSIG}

  setup do
    previous = Application.get_env(:ex_dns, :dnssec_algorithm_policy)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :dnssec_algorithm_policy)
        other -> Application.put_env(:ex_dns, :dnssec_algorithm_policy, other)
      end
    end)

    :ok
  end

  describe "signing_allowed?/1" do
    test "MUST-NOT algorithms are forbidden for signing" do
      refute AlgorithmPolicy.signing_allowed?(1)   # RSA/MD5
      refute AlgorithmPolicy.signing_allowed?(3)   # DSA/SHA-1
      refute AlgorithmPolicy.signing_allowed?(6)   # DSA-NSEC3-SHA1
      refute AlgorithmPolicy.signing_allowed?(12)  # GOST
    end

    test "MUST + RECOMMENDED + MAY algorithms are allowed for signing" do
      for algo <- [8, 13, 14, 15, 16] do
        assert AlgorithmPolicy.signing_allowed?(algo), "algorithm #{algo} should be sign-OK"
      end
    end

    test "NOT-RECOMMENDED algorithms are allowed by default" do
      for algo <- [5, 7, 10] do
        assert AlgorithmPolicy.signing_allowed?(algo)
      end
    end

    test "NOT-RECOMMENDED algorithms become disallowed in :strict mode" do
      Application.put_env(:ex_dns, :dnssec_algorithm_policy, strict: true)

      refute AlgorithmPolicy.signing_allowed?(5)   # RSA/SHA-1
      refute AlgorithmPolicy.signing_allowed?(7)   # RSASHA1-NSEC3-SHA1
      refute AlgorithmPolicy.signing_allowed?(10)  # RSA/SHA-512

      # MUST + RECOMMENDED still allowed under strict.
      assert AlgorithmPolicy.signing_allowed?(13)
    end
  end

  describe "validation_allowed?/1" do
    test "MUST-NOT-validate algorithms are refused" do
      refute AlgorithmPolicy.validation_allowed?(1)
      refute AlgorithmPolicy.validation_allowed?(3)
      refute AlgorithmPolicy.validation_allowed?(6)
    end

    test "every other algorithm is accepted for validation (RFC 8624 backward-compat)" do
      for algo <- [5, 7, 8, 10, 12, 13, 14, 15, 16] do
        assert AlgorithmPolicy.validation_allowed?(algo),
               "algorithm #{algo} should be validate-OK"
      end
    end
  end

  describe "status classifications" do
    test "sign_status/1 maps each algorithm to its RFC 8624 status" do
      assert :must = AlgorithmPolicy.sign_status(8)
      assert :must = AlgorithmPolicy.sign_status(13)
      assert :recommended = AlgorithmPolicy.sign_status(15)
      assert :may = AlgorithmPolicy.sign_status(14)
      assert :not_recommended = AlgorithmPolicy.sign_status(5)
      assert :must_not = AlgorithmPolicy.sign_status(1)
      assert :unknown = AlgorithmPolicy.sign_status(99)
    end

    test "validate_status/1 maps to validator-side classifications" do
      assert :must = AlgorithmPolicy.validate_status(8)
      assert :recommended = AlgorithmPolicy.validate_status(15)
      assert :may = AlgorithmPolicy.validate_status(12)
      assert :must_not = AlgorithmPolicy.validate_status(1)
    end
  end

  describe "Signer integration" do
    test "sign_rrset/4 refuses MUST-NOT algorithms" do
      dnskey = %DNSKEY{
        flags: 256,
        protocol: 3,
        algorithm: 1,
        public_key: <<0::128>>
      }

      records = [%A{name: "h.test", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}]

      assert {:error, :algorithm_disallowed} =
               Signer.sign_rrset(records, dnskey, <<>>, signer: "test")
    end
  end

  describe "Validator integration" do
    test "verify_rrset/3 refuses MUST-NOT algorithms" do
      dnskey = %DNSKEY{flags: 256, protocol: 3, algorithm: 1, public_key: <<0::128>>}

      rrsig = %RRSIG{
        name: "h.test",
        ttl: 60,
        class: :in,
        type_covered: :a,
        algorithm: 1,
        labels: 2,
        original_ttl: 60,
        signature_expiration: 1_800_000_000,
        signature_inception: 1_700_000_000,
        key_tag: Validator.key_tag(dnskey),
        signer: "test",
        signature: <<0::64>>
      }

      records = [%A{name: "h.test", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}]

      assert {:error, :algorithm_disallowed} = Validator.verify_rrset(records, rrsig, dnskey)
    end
  end

  describe "Rollover integration" do
    test "prepare_zsk_rollover/2 refuses MUST-NOT algorithms" do
      assert {:error, :algorithm_disallowed} =
               Rollover.prepare_zsk_rollover("example.test", algorithm: 1)
    end

    test "prepare_zsk_rollover/2 refuses NOT-RECOMMENDED algorithms in strict mode" do
      Application.put_env(:ex_dns, :dnssec_algorithm_policy, strict: true)

      assert {:error, :algorithm_disallowed} =
               Rollover.prepare_zsk_rollover("example.test", algorithm: 5)
    end

    test "prepare_zsk_rollover/2 accepts NOT-RECOMMENDED algorithms outside strict mode if generator supports them" do
      # We don't actually have a generator for algorithm 5 — that's
      # fine; the policy gate passes and the generator returns
      # :unsupported_algorithm. This proves the policy doesn't
      # block it.
      assert {:error, :unsupported_algorithm} =
               Rollover.prepare_zsk_rollover("example.test", algorithm: 5)
    end

    test "prepare_zsk_rollover/2 with algorithm 13 succeeds (the default)" do
      ExDns.DNSSEC.KeyStore.init()
      ExDns.DNSSEC.KeyStore.clear()

      assert {:ok, %DNSKEY{algorithm: 13}, _key_tag} =
               Rollover.prepare_zsk_rollover("example.test")
    end
  end
end
