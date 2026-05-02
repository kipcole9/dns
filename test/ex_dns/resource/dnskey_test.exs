defmodule ExDns.Resource.DNSKEYTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.DNSKEY

  test "round-trips a Zone-Signing Key" do
    record = %DNSKEY{
      flags: 256,
      protocol: 3,
      algorithm: 13,
      public_key: :crypto.strong_rand_bytes(64)
    }

    assert DNSKEY.decode(DNSKEY.encode(record), <<>>) == record
  end

  test "round-trips a Key-Signing Key (flags=257)" do
    record = %DNSKEY{
      flags: 257,
      protocol: 3,
      algorithm: 13,
      public_key: :crypto.strong_rand_bytes(64)
    }

    assert DNSKEY.decode(DNSKEY.encode(record), <<>>) == record
  end
end
