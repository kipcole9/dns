defmodule ExDns.Resource.MXTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.MX

  describe "decode/2 and encode/1" do
    test "round-trips a primary mail exchange" do
      record = %MX{priority: 10, server: "mail.example.com"}
      bytes = MX.encode(record)

      assert bytes == <<0, 10, 4, "mail", 7, "example", 3, "com", 0>>
      assert MX.decode(bytes, <<>>) == record
    end

    test "round-trips a backup mail exchange with high preference" do
      record = %MX{priority: 50_000, server: "backup.mx.example"}
      assert MX.decode(MX.encode(record), <<>>) == record
    end

    test "round-trips priority 0 (highest preference)" do
      record = %MX{priority: 0, server: "primary.example"}
      assert MX.decode(MX.encode(record), <<>>) == record
    end
  end
end
