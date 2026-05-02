defmodule ExDns.Resource.ATest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.A

  describe "decode/2 and encode/1" do
    test "round-trips a typical address" do
      record = %A{ipv4: {192, 0, 2, 1}}
      bytes = A.encode(record)

      assert bytes == <<192, 0, 2, 1>>
      assert A.decode(bytes, <<>>) == record
    end

    test "round-trips the documentation address 198.51.100.42" do
      record = %A{ipv4: {198, 51, 100, 42}}
      assert A.decode(A.encode(record), <<>>) == record
    end

    test "encode produces exactly four bytes" do
      assert byte_size(A.encode(%A{ipv4: {0, 0, 0, 0}})) == 4
      assert byte_size(A.encode(%A{ipv4: {255, 255, 255, 255}})) == 4
    end
  end
end
