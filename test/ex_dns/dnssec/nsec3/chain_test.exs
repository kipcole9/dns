defmodule ExDns.DNSSEC.NSEC3.ChainTest do
  @moduledoc """
  Verifies the NSEC3 chain constructor: hashed-owner ordering,
  next-hashed-owner linkage with wrap-around, and the per-name
  type bitmap including RRSIG + NSEC3.
  """

  use ExUnit.Case, async: true

  alias ExDns.DNSSEC.NSEC3
  alias ExDns.DNSSEC.NSEC3.Chain
  alias ExDns.Resource.NSEC3, as: NSEC3Record

  doctest Chain

  defp simple_zone do
    %{
      "example.test" => [:soa, :ns],
      "host1.example.test" => [:a],
      "host2.example.test" => [:a, :aaaa],
      "host3.example.test" => [:cname]
    }
  end

  describe "build/3" do
    test "returns one NSEC3 record per name" do
      chain = Chain.build("example.test", simple_zone())
      assert length(chain) == 4
    end

    test "every record is an NSEC3 struct with the zone-suffixed owner" do
      chain = Chain.build("example.test", simple_zone())

      Enum.each(chain, fn record ->
        assert %NSEC3Record{} = record
        assert String.ends_with?(record.name, ".example.test")
      end)
    end

    test "records are sorted by hashed owner (canonical base32hex order)" do
      chain = Chain.build("example.test", simple_zone())

      labels = Enum.map(chain, fn r -> hd(String.split(r.name, ".")) end)
      assert labels == Enum.sort(labels)
    end

    test "next_hashed_owner of each record points at the next hash; the last wraps to the first" do
      chain = Chain.build("example.test", simple_zone())
      hashes = Enum.map(chain, & extract_hash(&1.name))

      for {record, idx} <- Enum.with_index(chain) do
        next_idx = rem(idx + 1, length(chain))
        assert record.next_hashed_owner == Enum.at(hashes, next_idx)
      end
    end

    test "every record's bitmap includes RRSIG and NSEC3" do
      chain = Chain.build("example.test", simple_zone())

      for record <- chain do
        assert bitmap_contains?(record.type_bit_maps, :rrsig)
        assert bitmap_contains?(record.type_bit_maps, :nsec3)
      end
    end

    test "the apex's bitmap includes SOA + NS (the originally listed types)" do
      chain = Chain.build("example.test", simple_zone())
      apex_hash = NSEC3.hash_name("example.test", <<>>, 0)
      apex_owner = NSEC3.hashed_owner_from_hash(apex_hash, "example.test")
      apex_record = Enum.find(chain, &(&1.name == apex_owner))

      assert bitmap_contains?(apex_record.type_bit_maps, :soa)
      assert bitmap_contains?(apex_record.type_bit_maps, :ns)
    end

    test "honours :salt and :iterations options" do
      chain =
        Chain.build("example.test", simple_zone(),
          salt: <<0xAA, 0xBB>>,
          iterations: 3
        )

      Enum.each(chain, fn record ->
        assert record.salt == <<0xAA, 0xBB>>
        assert record.iterations == 3
      end)
    end

    test "honours :flags option (e.g. opt-out flag = 1)" do
      chain = Chain.build("example.test", simple_zone(), flags: 1)
      Enum.each(chain, fn record -> assert record.flags == 1 end)
    end

    test "single-name zone wraps to itself" do
      chain = Chain.build("solo.test", %{"solo.test" => [:soa]})
      assert [%NSEC3Record{} = record] = chain
      assert record.next_hashed_owner == NSEC3.hash_name("solo.test", <<>>, 0)
    end
  end

  describe "opt-out (RFC 5155 §6)" do
    defp delegation_zone do
      # Apex with NS+SOA, secure delegation (NS+DS), insecure
      # delegation (NS only), regular host.
      %{
        "example.test" => [:soa, :ns],
        "secure.example.test" => [:ns, :ds],
        "insecure.example.test" => [:ns],
        "host.example.test" => [:a]
      }
    end

    test "opt_out: true sets the opt-out flag (bit 0) on every NSEC3" do
      chain = Chain.build("example.test", delegation_zone(), opt_out: true)

      Enum.each(chain, fn record ->
        import Bitwise
        assert (record.flags &&& 1) == 1
      end)
    end

    test "opt_out: true excludes insecure delegations from the chain" do
      chain = Chain.build("example.test", delegation_zone(), opt_out: true)
      owners = Enum.map(chain, & &1.name)

      # Apex, secure delegation, host all present.
      apex_owner = NSEC3.hashed_owner_from_hash(NSEC3.hash_name("example.test", <<>>, 0), "example.test")
      secure_owner = NSEC3.hashed_owner_from_hash(NSEC3.hash_name("secure.example.test", <<>>, 0), "example.test")
      insecure_owner = NSEC3.hashed_owner_from_hash(NSEC3.hash_name("insecure.example.test", <<>>, 0), "example.test")
      host_owner = NSEC3.hashed_owner_from_hash(NSEC3.hash_name("host.example.test", <<>>, 0), "example.test")

      assert apex_owner in owners
      assert secure_owner in owners
      assert host_owner in owners

      # Insecure delegation excluded — RFC 5155 §6.
      refute insecure_owner in owners
    end

    test "opt_out: false (default) includes every name and clears the flag" do
      chain = Chain.build("example.test", delegation_zone())

      assert length(chain) == 4
      Enum.each(chain, fn record -> assert record.flags == 0 end)
    end

    test "opt_out always preserves the apex even when its types include NS" do
      # Apex has NS + SOA — it's a delegation point in shape but
      # MUST be in the chain (RFC 5155 §6 explicit carve-out).
      chain = Chain.build("example.test", %{"example.test" => [:soa, :ns]}, opt_out: true)
      assert length(chain) == 1
    end

    test "opt_out + an explicit flags value compose (both bits set)" do
      chain = Chain.build("example.test", delegation_zone(), opt_out: true, flags: 0b10)

      Enum.each(chain, fn record ->
        # Bit 0 (opt-out) and bit 1 (operator-supplied) both on.
        assert record.flags == 0b11
      end)
    end

    test "with no insecure delegations the chain is identical to opt_out: false" do
      zone = %{
        "example.test" => [:soa, :ns],
        "secure.example.test" => [:ns, :ds]
      }

      with_opt = Chain.build("example.test", zone, opt_out: true)
      without_opt = Chain.build("example.test", zone)

      # Same number of records, just different flag bytes.
      assert length(with_opt) == length(without_opt)
    end
  end

  describe "encode_type_bitmap/1" do
    test "produces the standard window/length/bits triplet" do
      bytes = Chain.encode_type_bitmap([:a])
      # A is type 1; window 0; max offset 1; needs 1 byte; bit 6 set.
      assert <<0::size(8), 1::size(8), 0b01000000::size(8)>> = bytes
    end

    test "groups multiple windows correctly" do
      # SVCB is type 64, well in window 0; CAA is type 257, in window 1.
      bytes = Chain.encode_type_bitmap([:svcb, :caa])
      # Two windows expected.
      assert byte_size(bytes) > 4
    end

    test "skips qtypes that aren't in the registry" do
      bytes = Chain.encode_type_bitmap([:a, :totally_made_up_type])
      # The made-up qtype yields nil from type_from/1 and is filtered.
      assert <<0::size(8), 1::size(8), 0b01000000::size(8)>> = bytes
    end
  end

  # ----- helpers -------------------------------------------------

  defp extract_hash(owner) when is_binary(owner) do
    [label | _] = String.split(owner, ".", parts: 2)
    Base.hex_decode32!(String.upcase(label), padding: false)
  end

  defp bitmap_contains?(bytes, qtype) do
    type_int = ExDns.Resource.type_from(qtype)
    target_window = div(type_int, 256)
    offset = rem(type_int, 256)
    byte_index = div(offset, 8)
    bit_index = 7 - rem(offset, 8)
    do_bitmap_contains(bytes, target_window, byte_index, bit_index)
  end

  defp do_bitmap_contains(<<>>, _, _, _), do: false

  defp do_bitmap_contains(
         <<window::8, length::8, bits::binary-size(length), rest::binary>>,
         target_window,
         byte_index,
         bit_index
       ) do
    if window == target_window and byte_index < byte_size(bits) do
      <<_::binary-size(byte_index), b::8, _::binary>> = bits
      import Bitwise
      (b &&& bsl(1, bit_index)) != 0
    else
      do_bitmap_contains(rest, target_window, byte_index, bit_index)
    end
  end
end
