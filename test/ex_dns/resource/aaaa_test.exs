defmodule ExDns.Resource.AAAATest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.AAAA

  describe "decode/2 and encode/1" do
    test "round-trips a documentation address" do
      record = %AAAA{ipv6: {0x2001, 0x0db8, 0, 0, 0, 0, 0, 1}}
      bytes = AAAA.encode(record)

      assert byte_size(bytes) == 16
      assert AAAA.decode(bytes, <<>>) == record
    end

    test "round-trips loopback" do
      record = %AAAA{ipv6: {0, 0, 0, 0, 0, 0, 0, 1}}
      assert AAAA.decode(AAAA.encode(record), <<>>) == record
    end

    test "round-trips an all-set address" do
      record = %AAAA{ipv6: {0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF}}
      assert AAAA.decode(AAAA.encode(record), <<>>) == record
    end
  end
end
