defmodule ExDns.Resource.CAATest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.CAA

  describe "decode/2 and encode/1" do
    test "round-trips a basic CAA issue record" do
      record = %CAA{flags: 0, tag: "issue", value: "letsencrypt.org"}
      bytes = CAA.encode(record)
      assert bytes == <<0, 5, "issue", "letsencrypt.org">>
      assert CAA.decode(bytes, <<>>) == record
    end

    test "round-trips a critical (flags=128) record" do
      record = %CAA{flags: 128, tag: "issuewild", value: ";"}
      assert CAA.decode(CAA.encode(record), <<>>) == record
    end

    test "round-trips an iodef record with a URL value" do
      record = %CAA{flags: 0, tag: "iodef", value: "mailto:abuse@example.com"}
      assert CAA.decode(CAA.encode(record), <<>>) == record
    end
  end
end
