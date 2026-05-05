defmodule ExDns.EDNSAlgorithmSignalingTest do
  @moduledoc """
  Verifies the RFC 6975 DAU/DHU/N3U codec and the "what we
  support" reporter that drives outbound advertisement.
  """

  use ExUnit.Case, async: true

  alias ExDns.EDNSAlgorithmSignaling, as: Sig

  doctest Sig

  describe "option_code/1" do
    test "maps each kind to its IANA code" do
      assert 5 = Sig.option_code(:dau)
      assert 6 = Sig.option_code(:dhu)
      assert 7 = Sig.option_code(:n3u)
    end
  end

  describe "encode_option/2 + decode_payload/1 round-trip" do
    test "DAU with multiple algorithms" do
      {code, payload} = Sig.encode_option(:dau, [8, 13, 15])
      assert code == 5
      assert Sig.decode_payload(payload) == [8, 13, 15]
    end

    test "DHU with one algorithm" do
      {code, payload} = Sig.encode_option(:dhu, [2])
      assert code == 6
      assert Sig.decode_payload(payload) == [2]
    end

    test "N3U with empty list produces an empty payload" do
      {code, payload} = Sig.encode_option(:n3u, [])
      assert code == 7
      assert payload == <<>>
      assert Sig.decode_payload(payload) == []
    end
  end

  describe "find_in_options/1" do
    test "returns empty map when no signaling options are present" do
      assert %{} = Sig.find_in_options([])
      assert %{} = Sig.find_in_options([{10, "cookie"}, {12, "padding"}])
    end

    test "extracts a single DAU" do
      assert %{dau: [8, 13, 15]} =
               Sig.find_in_options([{5, <<8, 13, 15>>}])
    end

    test "extracts all three when present together" do
      options = [
        {5, <<8, 13>>},
        {6, <<2>>},
        {7, <<1>>}
      ]

      assert %{dau: [8, 13], dhu: [2], n3u: [1]} = Sig.find_in_options(options)
    end

    test "ignores unrelated OPT options" do
      options = [
        {10, "cookie-bytes"},
        {5, <<13>>},
        {99, "unknown"}
      ]

      assert %{dau: [13]} = Sig.find_in_options(options)
    end
  end

  describe "supported/1" do
    test "DAU includes algorithms our validator can verify" do
      dau = Sig.supported(:dau)
      # ECDSA P-256 (13) and Ed25519 (15) are MUST/RECOMMENDED;
      # both should be advertised.
      assert 13 in dau
      assert 15 in dau
      # RSA/SHA-256 (8) is MUST-validate.
      assert 8 in dau
    end

    test "DAU excludes RFC 8624 MUST-NOT-validate algorithms" do
      dau = Sig.supported(:dau)
      refute 1 in dau    # RSA/MD5
      refute 3 in dau    # DSA/SHA-1
      refute 6 in dau    # DSA-NSEC3-SHA1
    end

    test "DHU advertises SHA-1 + SHA-256 (the digest types we compute)" do
      assert [1, 2] = Sig.supported(:dhu)
    end

    test "N3U advertises only SHA-1 (the only RFC 5155 hash)" do
      assert [1] = Sig.supported(:n3u)
    end
  end

  test "all three options can be built from supported/1 and round-tripped" do
    options =
      for kind <- [:dau, :dhu, :n3u] do
        Sig.encode_option(kind, Sig.supported(kind))
      end

    decoded = Sig.find_in_options(options)
    assert Map.keys(decoded) |> Enum.sort() == [:dau, :dhu, :n3u]
    assert decoded.dau == Sig.supported(:dau)
    assert decoded.dhu == Sig.supported(:dhu)
    assert decoded.n3u == Sig.supported(:n3u)
  end
end
