defmodule ExDns.Resource.CNAMETest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.CNAME

  describe "decode/2 and encode/1" do
    test "round-trips a canonical name" do
      record = %CNAME{server: "www.example.com"}
      bytes = CNAME.encode(record)

      assert bytes == <<3, "www", 7, "example", 3, "com", 0>>
      assert CNAME.decode(bytes, <<>>) == record
    end

    test "round-trips a deeper subdomain alias" do
      record = %CNAME{server: "a.b.c.example.com"}
      assert CNAME.decode(CNAME.encode(record), <<>>) == record
    end
  end
end
