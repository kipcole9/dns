defmodule ExDns.Resource.DNAMETest do
  use ExUnit.Case, async: true

  alias ExDns.Resource.DNAME

  test "round-trips a typical DNAME" do
    record = %DNAME{target: "new.example.com"}
    assert DNAME.decode(DNAME.encode(record), <<>>) == record
  end
end
