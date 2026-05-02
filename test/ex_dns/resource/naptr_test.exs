defmodule ExDns.Resource.NAPTRTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.NAPTR

  test "round-trips a typical SIP NAPTR" do
    record = %NAPTR{
      order: 100,
      preference: 10,
      flags: "S",
      services: "SIP+D2U",
      regexp: "",
      replacement: "_sip._udp.example.com"
    }

    assert NAPTR.decode(NAPTR.encode(record), <<>>) == record
  end

  test "round-trips a regex-bearing NAPTR" do
    record = %NAPTR{
      order: 100,
      preference: 50,
      flags: "U",
      services: "E2U+sip",
      regexp: ~S"!^.*$!sip:user@example.com!",
      replacement: ""
    }

    assert NAPTR.decode(NAPTR.encode(record), <<>>) == record
  end
end
