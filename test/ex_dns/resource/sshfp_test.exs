defmodule ExDns.Resource.SSHFPTest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.SSHFP

  test "round-trips a SHA-256 fingerprint for an Ed25519 key" do
    record = %SSHFP{
      algorithm: 4,
      fp_type: 2,
      fingerprint: :crypto.strong_rand_bytes(32)
    }

    assert SSHFP.decode(SSHFP.encode(record), <<>>) == record
  end
end
