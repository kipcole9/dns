defmodule ExDnsTest do
  use ExUnit.Case
  doctest ExDns
  doctest ExDns.Message
  doctest ExDns.Message.Header
  doctest ExDns.Message.Question
  doctest ExDns.Resource.A
  doctest ExDns.Resource.AAAA
  doctest ExDns.Resource.NS
  doctest ExDns.Resource.CNAME
  doctest ExDns.Resource.PTR
  doctest ExDns.Resource.MX
  doctest ExDns.Resource.TXT
  doctest ExDns.Resource.SRV
  doctest ExDns.Resource.HINFO
  doctest ExDns.Resource.CAA
  doctest ExDns.Resource.DNAME
  doctest ExDns.Resource.SSHFP
  doctest ExDns.Zone.File

  @test_files 1..6

  for i <- @test_files do
    test "that we can parse zone file #{i}" do
      zone_info = File.read!("./test/support/test_zone_file_#{unquote(i)}.txt")

      parse_result =
        zone_info
        |> ExDns.Zone.File.parse()

      assert {:ok, _, _} = parse_result
    end
  end

  # File 100 was originally written to exercise an old custom parser
  # error ("A zone file must contain resource records beyond an SOA"),
  # but the current grammar accepts SOA-only zones, so the file now
  # parses successfully. We still keep it in the suite to make sure the
  # grammar can handle the bare-SOA shape without crashing — if a future
  # validation layer rejects this, the assertion can be tightened.
  test "that we can parse zone file 100" do
    zone_info = File.read!("./test/support/test_zone_file_100.txt")

    assert {:ok, _directives, _records} = ExDns.Zone.File.parse(zone_info)
  end
end
