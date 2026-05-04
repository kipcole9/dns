defmodule ExDns.DNSSEC.AggressiveNSECTest do
  @moduledoc """
  Verifies the NSEC range-proof primitives used by aggressive use
  of cached NSEC records (RFC 8198).
  """

  use ExUnit.Case, async: true

  alias ExDns.DNSSEC.AggressiveNSEC
  alias ExDns.Resource.NSEC

  doctest AggressiveNSEC

  # Build a type bitmap for a given list of qtypes.
  defp bitmap(qtypes) do
    qtypes
    |> Enum.map(&ExDns.Resource.type_from/1)
    |> Enum.group_by(&div(&1, 256))
    |> Enum.map(fn {window, types} ->
      max_offset = types |> Enum.map(&rem(&1, 256)) |> Enum.max()
      bytes = div(max_offset, 8) + 1
      empty = :binary.copy(<<0>>, bytes)

      bits =
        Enum.reduce(types, empty, fn t, acc ->
          offset = rem(t, 256)
          byte_idx = div(offset, 8)
          bit_idx = 7 - rem(offset, 8)
          <<head::binary-size(byte_idx), b::8, tail::binary>> = acc
          import Bitwise
          <<head::binary, b ||| bsl(1, bit_idx)::8, tail::binary>>
        end)

      <<window::8, bytes::8, bits::binary>>
    end)
    |> IO.iodata_to_binary()
  end

  defp nsec(name, next, types) do
    %NSEC{name: name, ttl: 60, class: :in, next_domain: next, type_bit_maps: bitmap(types)}
  end

  describe "canonical_compare/2" do
    test "label-by-label comparison from the rightmost label" do
      # com sorts before example.com sorts before alpha.example.com
      assert :lt = AggressiveNSEC.canonical_compare("com", "example.com")
      assert :lt = AggressiveNSEC.canonical_compare("example.com", "alpha.example.com")
      assert :gt = AggressiveNSEC.canonical_compare("alpha.example.com", "com")
    end

    test "case-insensitive" do
      assert :eq = AggressiveNSEC.canonical_compare("Example.COM", "example.com")
    end

    test "trailing dots normalised" do
      assert :eq = AggressiveNSEC.canonical_compare("example.com.", "example.com")
    end
  end

  describe "proves_nxdomain?/2" do
    test "proves NXDOMAIN for a name strictly between owner and next" do
      records = [nsec("alpha.example.com", "echo.example.com", [:a])]

      assert {:yes, _} = AggressiveNSEC.proves_nxdomain?("charlie.example.com", records)
      assert {:yes, _} = AggressiveNSEC.proves_nxdomain?("bravo.example.com", records)
    end

    test "does not prove NXDOMAIN for the owner name itself" do
      records = [nsec("alpha.example.com", "echo.example.com", [:a])]
      assert :no = AggressiveNSEC.proves_nxdomain?("alpha.example.com", records)
    end

    test "does not prove NXDOMAIN outside the interval" do
      records = [nsec("alpha.example.com", "echo.example.com", [:a])]
      assert :no = AggressiveNSEC.proves_nxdomain?("zulu.example.com", records)
      assert :no = AggressiveNSEC.proves_nxdomain?("aardvark.example.com", records)
    end

    test "empty record list returns :no" do
      assert :no = AggressiveNSEC.proves_nxdomain?("anything.test", [])
    end

    test "first matching NSEC wins when multiple are present" do
      records = [
        nsec("alpha.example.com", "echo.example.com", [:a]),
        nsec("foxtrot.example.com", "kilo.example.com", [:a])
      ]

      assert {:yes, %NSEC{name: "alpha.example.com"}} =
               AggressiveNSEC.proves_nxdomain?("charlie.example.com", records)

      assert {:yes, %NSEC{name: "foxtrot.example.com"}} =
               AggressiveNSEC.proves_nxdomain?("hotel.example.com", records)
    end
  end

  describe "proves_nodata?/3" do
    test "proves NODATA when owner exists but qtype not in bitmap" do
      records = [nsec("host.example.com", "next.example.com", [:a])]

      # MX is not in the bitmap → NODATA proven.
      assert {:yes, _} = AggressiveNSEC.proves_nodata?("host.example.com", :mx, records)
      assert {:yes, _} = AggressiveNSEC.proves_nodata?("host.example.com", :aaaa, records)
    end

    test "does not prove NODATA when qtype IS in bitmap" do
      records = [nsec("host.example.com", "next.example.com", [:a, :mx])]

      assert :no = AggressiveNSEC.proves_nodata?("host.example.com", :a, records)
      assert :no = AggressiveNSEC.proves_nodata?("host.example.com", :mx, records)
    end

    test "doesn't prove NODATA for a different name" do
      records = [nsec("host.example.com", "next.example.com", [:a])]
      assert :no = AggressiveNSEC.proves_nodata?("other.example.com", :mx, records)
    end
  end
end
