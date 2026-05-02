defmodule ExDns.Resource.RRSIGTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.RRSIG

  test "round-trips an RRSIG covering A records" do
    record = %RRSIG{
      type_covered: :a,
      algorithm: 13,
      labels: 2,
      original_ttl: 3600,
      signature_expiration: 1_700_000_000,
      signature_inception: 1_690_000_000,
      key_tag: 12_345,
      signer: "example.com",
      signature: :crypto.strong_rand_bytes(64)
    }

    assert RRSIG.decode(RRSIG.encode(record), <<>>) == record
  end
end
