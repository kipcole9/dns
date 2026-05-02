defmodule ExDns.Resource.PTRTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.PTR

  describe "decode/2 and encode/1" do
    test "round-trips a reverse-DNS pointer" do
      record = %PTR{pointer: "host.example.com"}
      assert PTR.decode(PTR.encode(record), <<>>) == record
    end

    test "round-trips an in-addr.arpa target" do
      record = %PTR{pointer: "1.2.0.192.in-addr.arpa"}
      bytes = PTR.encode(record)
      assert PTR.decode(bytes, <<>>) == record
    end
  end
end
