defmodule ExDns.Resource.LOCTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.LOC

  test "round-trips a LOC record" do
    record = %LOC{
      version: 0,
      size: 0x12,
      horiz_pre: 0x16,
      vert_pre: 0x13,
      latitude: 0x8000_0000 + 30_000_000,
      longitude: 0x8000_0000 - 90_000_000,
      altitude: 100_000_00
    }

    bytes = LOC.encode(record)
    assert byte_size(bytes) == 16
    assert LOC.decode(bytes, <<>>) == record
  end
end
