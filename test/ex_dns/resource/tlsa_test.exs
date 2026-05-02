defmodule ExDns.Resource.TLSATest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.TLSA

  test "round-trips a DANE-EE SHA-256 record" do
    record = %TLSA{
      cert_usage: 3,
      selector: 1,
      matching_type: 1,
      cert_data: :crypto.hash(:sha256, "example cert")
    }

    assert TLSA.decode(TLSA.encode(record), <<>>) == record
  end
end
