defmodule ExDns.Resource.SVCBTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.SVCB

  test "round-trips an alias-mode SVCB (priority 0, no params)" do
    record = %SVCB{priority: 0, target: "alt.example.com", params: []}
    assert SVCB.decode(SVCB.encode(record), <<>>) == record
  end

  test "round-trips a service-mode SVCB with alpn and port" do
    record = %SVCB{
      priority: 1,
      target: "svc.example.com",
      params: [
        # alpn = "h2,h3"
        {1, <<2, "h2", 2, "h3">>},
        # port = 443
        {3, <<0x01, 0xBB>>}
      ]
    }

    assert SVCB.decode(SVCB.encode(record), <<>>) == record
  end
end
