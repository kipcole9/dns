defmodule ExDns.Resource.SRVTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.SRV

  describe "decode/2 and encode/1" do
    test "round-trips an XMPP service record" do
      record = %SRV{priority: 10, weight: 60, port: 8080, target: "_xmpp.example"}
      bytes = SRV.encode(record)

      assert bytes == <<0, 10, 0, 60, 0x1F, 0x90, 5, "_xmpp", 7, "example", 0>>
      assert SRV.decode(bytes, <<>>) == record
    end

    test "round-trips with priority and weight at extremes" do
      record = %SRV{priority: 0, weight: 65_535, port: 53, target: "ns.example.com"}
      assert SRV.decode(SRV.encode(record), <<>>) == record
    end
  end
end
