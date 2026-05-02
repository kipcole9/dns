defmodule ExDns.Resource.NSEC3Test do
  use ExUnit.Case, async: true

  alias ExDns.Resource.NSEC3

  test "round-trips an NSEC3 record with salt + next-hashed-owner + bitmap" do
    record = %NSEC3{
      hash_algorithm: 1,
      flags: 0,
      iterations: 10,
      salt: <<0xAA, 0xBB>>,
      next_hashed_owner: :crypto.hash(:sha, "label"),
      type_bit_maps: <<0, 6, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03>>
    }

    assert NSEC3.decode(NSEC3.encode(record), <<>>) == record
  end

  test "round-trips with empty salt" do
    record = %NSEC3{
      hash_algorithm: 1,
      flags: 1,
      iterations: 0,
      salt: <<>>,
      next_hashed_owner: :crypto.hash(:sha, "x"),
      type_bit_maps: <<>>
    }

    assert NSEC3.decode(NSEC3.encode(record), <<>>) == record
  end
end
