defmodule ExDns.Resource.NSTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.NS

  describe "decode/2 and encode/1" do
    test "round-trips a single nameserver" do
      record = %NS{server: "ns1.example.com"}
      bytes = NS.encode(record)

      assert bytes == <<3, "ns1", 7, "example", 3, "com", 0>>
      assert NS.decode(bytes, <<>>) == record
    end

    test "round-trips a deeper subdomain" do
      record = %NS{server: "a.b.c.d.example"}
      assert NS.decode(NS.encode(record), <<>>) == record
    end

    test "decodes a name that uses a compression pointer" do
      header_pad = <<0::96>>
      first_name = <<7, "example", 3, "com", 0>>
      pointer_only = <<0b11::2, 12::14>>
      message = header_pad <> first_name <> pointer_only

      record = NS.decode(pointer_only, message)
      assert record == %NS{server: "example.com"}
    end
  end
end
