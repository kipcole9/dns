defmodule ExDns.DNSSEC.NSECTest do
  use ExUnit.Case, async: true

  alias ExDns.DNSSEC.NSEC
  alias ExDns.Resource.{A, AAAA, MX, NS, SOA, TXT}
  alias ExDns.Resource.NSEC, as: NSECRR

  defp soa(name) do
    %SOA{
      name: name,
      ttl: 86_400,
      class: :in,
      mname: "ns.#{name}",
      email: "admin.#{name}",
      serial: 1,
      refresh: 7200,
      retry: 3600,
      expire: 1_209_600,
      minimum: 3600
    }
  end

  describe "encode_type_bitmap/1" do
    test "encodes a single type in window 0" do
      assert NSEC.encode_type_bitmap([1]) == <<0, 1, 0b0100_0000>>
    end

    test "encodes types A, NS, SOA, MX, TXT, AAAA, RRSIG, NSEC" do
      types = [1, 2, 6, 15, 16, 28, 46, 47]
      bitmap = NSEC.encode_type_bitmap(types)
      <<window, length, body::binary>> = bitmap

      assert window == 0
      assert byte_size(body) == length

      # Decode it back: each byte's bit n (MSB-first) → type window*256 + byte_offset*8 + n
      decoded =
        body
        |> :binary.bin_to_list()
        |> Enum.with_index()
        |> Enum.flat_map(fn {byte, byte_idx} ->
          for bit_idx <- 0..7,
              Bitwise.band(byte, Bitwise.bsl(1, 7 - bit_idx)) != 0,
              do: byte_idx * 8 + bit_idx
        end)

      assert Enum.sort(decoded) == Enum.sort(types)
    end

    test "spans multiple windows for high-numbered types" do
      # type 256 falls in window 1
      bitmap = NSEC.encode_type_bitmap([1, 256])

      <<w0, l0, _body0::binary-size(l0), w1, l1, _body1::binary-size(l1)>> = bitmap
      assert w0 == 0
      assert w1 == 1
    end
  end

  describe "sort_canonically/1" do
    test "sorts names by reversed-label order (TLD-first)" do
      names = ["a.example.com", "example.com", "b.example.com", "x.b.example.com"]
      sorted = NSEC.sort_canonically(names)

      assert sorted == [
               "example.com",
               "a.example.com",
               "b.example.com",
               "x.b.example.com"
             ]
    end

    test "is case-insensitive" do
      assert NSEC.sort_canonically(["B.example", "a.example"]) == ["a.example", "B.example"]
    end
  end

  describe "generate/3" do
    test "produces an NSEC chain that wraps to the apex" do
      records = [
        soa("example.com"),
        %NS{name: "example.com", ttl: 86_400, class: :in, server: "ns.example.com"},
        %A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}},
        %A{name: "host.example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 2}},
        %AAAA{name: "host.example.com", ttl: 60, class: :in, ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}},
        %MX{name: "mail.example.com", ttl: 60, class: :in, priority: 10, server: "smtp.example.com"}
      ]

      chain = NSEC.generate("example.com", records)

      # Three distinct owners → three NSEC records.
      assert length(chain) == 3
      owners = Enum.map(chain, & &1.name)
      assert owners == ["example.com", "host.example.com", "mail.example.com"]

      # Chain wraps: last NSEC's next_domain is the apex.
      assert List.last(chain).next_domain == "example.com"
      # First → second
      assert hd(chain).next_domain == "host.example.com"
    end

    test "each NSEC's bitmap includes the types present at its owner plus NSEC and RRSIG" do
      records = [
        soa("example.com"),
        %TXT{name: "example.com", ttl: 60, class: :in, strings: ["v=spf1 -all"]}
      ]

      [nsec] = NSEC.generate("example.com", records)
      assert %NSECRR{} =nsec
      # Bitmap should contain SOA (6), TXT (16), RRSIG (46), NSEC (47).
      types = decode_bitmap(nsec.type_bit_maps)
      assert 6 in types
      assert 16 in types
      assert 46 in types
      assert 47 in types
    end

    test "yields an empty chain for a zone with no records" do
      assert NSEC.generate("empty.test", []) == []
    end
  end

  describe "for_owner/2 and covering/2" do
    test "for_owner finds the NSEC whose name matches the qname" do
      records = [
        soa("example.com"),
        %A{name: "host.example.com", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}
      ]

      chain = NSEC.generate("example.com", records)
      assert %NSECRR{} =NSEC.for_owner(chain, "host.example.com")
      assert NSEC.for_owner(chain, "missing.example.com") == nil
    end

    test "covering returns the NSEC whose owner < qname < next_domain" do
      records = [
        soa("example.com"),
        %A{name: "a.example.com", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}},
        %A{name: "z.example.com", ttl: 60, class: :in, ipv4: {1, 2, 3, 5}}
      ]

      chain = NSEC.generate("example.com", records)
      cover = NSEC.covering(chain, "m.example.com")
      assert cover != nil
      assert cover.name == "a.example.com"
    end
  end

  defp decode_bitmap(bitmap) do
    decode_bitmap(bitmap, [])
  end

  defp decode_bitmap(<<>>, acc), do: Enum.sort(acc)

  defp decode_bitmap(<<window, length, rest_with_body::binary>>, acc) do
    <<body::binary-size(^length), rest::binary>> = rest_with_body
    types =
      body
      |> :binary.bin_to_list()
      |> Enum.with_index()
      |> Enum.flat_map(fn {byte, byte_idx} ->
        for bit_idx <- 0..7,
            Bitwise.band(byte, Bitwise.bsl(1, 7 - bit_idx)) != 0,
            do: window * 256 + byte_idx * 8 + bit_idx
      end)

    decode_bitmap(rest, acc ++ types)
  end
end
