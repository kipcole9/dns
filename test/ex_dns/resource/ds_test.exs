defmodule ExDns.Resource.DSTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.DS

  test "round-trips a SHA-256 DS record" do
    record = %DS{
      key_tag: 12_345,
      algorithm: 13,
      digest_type: 2,
      digest: :crypto.hash(:sha256, "DNSKEY material")
    }

    assert DS.decode(DS.encode(record), <<>>) == record
  end
end
