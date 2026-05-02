defmodule ExDns.Resource.TXTTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.TXT

  describe "decode/2 and encode/1" do
    test "round-trips a single short string" do
      record = %TXT{strings: ["v=spf1 -all"]}
      assert TXT.decode(TXT.encode(record), <<>>) == record
    end

    test "round-trips multiple strings within one record" do
      record = %TXT{strings: ["hello", "world", "!"]}
      assert TXT.decode(TXT.encode(record), <<>>) == record
    end

    test "round-trips a max-length character string (255 bytes)" do
      max_string = String.duplicate("x", 255)
      record = %TXT{strings: [max_string]}
      bytes = TXT.encode(record)

      assert byte_size(bytes) == 256
      assert TXT.decode(bytes, <<>>) == record
    end

    test "encodes the empty list as zero RDATA bytes" do
      assert TXT.encode(%TXT{strings: []}) == <<>>
    end
  end
end
