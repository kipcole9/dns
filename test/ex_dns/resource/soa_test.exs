defmodule ExDns.Resource.SOATest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.SOA

  describe "decode/2 and encode/1" do
    test "round-trips a typical SOA record" do
      record = %SOA{
        mname: "ns1.example.com",
        email: "hostmaster.example.com",
        serial: 2_026_050_201,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minimum: 3600
      }

      bytes = SOA.encode(record)
      assert SOA.decode(bytes, <<>>) == record
    end

    test "round-trips with maximum-value 32-bit fields" do
      record = %SOA{
        mname: "primary.example",
        email: "admin.example",
        serial: 0xFFFFFFFF,
        refresh: 0xFFFFFFFF,
        retry: 0xFFFFFFFF,
        expire: 0xFFFFFFFF,
        minimum: 0xFFFFFFFF
      }

      assert SOA.decode(SOA.encode(record), <<>>) == record
    end
  end
end
