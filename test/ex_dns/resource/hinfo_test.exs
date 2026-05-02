defmodule ExDns.Resource.HINFOTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.HINFO

  describe "decode/2 and encode/1" do
    test "round-trips a typical CPU/OS pair" do
      record = %HINFO{cpu: "x86_64", os: "Linux"}
      bytes = HINFO.encode(record)

      assert bytes == <<6, "x86_64", 5, "Linux">>
      assert HINFO.decode(bytes, <<>>) == record
    end

    test "round-trips empty CPU and OS" do
      record = %HINFO{cpu: "", os: ""}
      assert HINFO.decode(HINFO.encode(record), <<>>) == record
    end
  end
end
