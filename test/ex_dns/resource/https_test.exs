defmodule ExDns.Resource.HTTPSTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.HTTPS

  test "round-trips an alias-mode HTTPS (priority 0)" do
    record = %HTTPS{priority: 0, target: "alt.example.com", params: []}
    assert HTTPS.decode(HTTPS.encode(record), <<>>) == record
  end

  test "round-trips a service-mode HTTPS with alpn=h3" do
    record = %HTTPS{
      priority: 1,
      target: "svc.example.com",
      params: [{1, <<2, "h3">>}]
    }

    assert HTTPS.decode(HTTPS.encode(record), <<>>) == record
  end
end
