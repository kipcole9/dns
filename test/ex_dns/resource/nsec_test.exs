defmodule ExDns.Resource.NSECTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.NSEC

  test "round-trips an NSEC record with a synthetic bitmap" do
    record = %NSEC{
      next_domain: "next.example.com",
      # Window 0, 8 bitmap bytes — bits set for types in range 0..63
      type_bit_maps: <<0, 8, 0b00100010, 0, 0, 0, 0b00100000, 0, 0, 0>>
    }

    assert NSEC.decode(NSEC.encode(record), <<>>) == record
  end
end
