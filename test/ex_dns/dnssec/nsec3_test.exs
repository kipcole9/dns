defmodule ExDns.DNSSEC.NSEC3Test do
  @moduledoc """
  Verifies the NSEC3 hash + owner-name primitives match RFC 5155
  Appendix A test vectors.
  """

  use ExUnit.Case, async: true

  alias ExDns.DNSSEC.NSEC3

  doctest NSEC3

  describe "hash_name/3" do
    test "produces a 20-byte SHA-1 digest regardless of input" do
      assert byte_size(NSEC3.hash_name("example.com", <<>>, 0)) == 20
      assert byte_size(NSEC3.hash_name("a.example.com", "salt", 5)) == 20
    end

    test "is deterministic for the same inputs" do
      a = NSEC3.hash_name("host.example.com", <<0xAA, 0xBB>>, 10)
      b = NSEC3.hash_name("host.example.com", <<0xAA, 0xBB>>, 10)
      assert a == b
    end

    test "is case-insensitive on the input name" do
      a = NSEC3.hash_name("HOST.example.COM", <<>>, 0)
      b = NSEC3.hash_name("host.example.com", <<>>, 0)
      assert a == b
    end

    test "produces different hashes for different iteration counts" do
      a = NSEC3.hash_name("example.com", <<>>, 0)
      b = NSEC3.hash_name("example.com", <<>>, 1)
      refute a == b
    end

    test "matches RFC 5155 Appendix A: example.com / iterations=12 / salt=AABBCCDD" do
      # Per RFC 5155 Appendix A:
      #   example.            NSEC3 1 1 12 aabbccdd  0p9mhaveqvm6t7vbl5lop2u3t2rp3tom
      # Owner-name hash is the leading label.
      hash = NSEC3.hash_name("example", <<0xAA, 0xBB, 0xCC, 0xDD>>, 12)
      encoded = Base.hex_encode32(hash, case: :lower, padding: false)

      assert encoded == "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"
    end
  end

  describe "hashed_owner/3" do
    test "appends the zone suffix to the base32hex hash" do
      owner = NSEC3.hashed_owner("host.example.com", "example.com")
      assert String.ends_with?(owner, ".example.com")
    end

    test "produces lower-case base32hex labels" do
      owner = NSEC3.hashed_owner("host.example.com", "example.com")
      [label, _zone] = String.split(owner, ".", parts: 2)
      assert String.downcase(label) == label
    end

    test "honours the :salt + :iterations options" do
      a = NSEC3.hashed_owner("x.test", "test")
      b = NSEC3.hashed_owner("x.test", "test", salt: "salt", iterations: 5)
      refute a == b
    end
  end
end
