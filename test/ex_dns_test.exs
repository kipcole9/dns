defmodule ExDnsTest do
  use ExUnit.Case
  doctest ExDns

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

  # And for a file that has an error
  test "that we can parse zone file 100" do
    zone_info = File.read!("./test/support/test_zone_file_100.txt")

    parse_result =
      zone_info
      |> ExDns.Zone.File.parse()

    assert {:error, {1, :zone_parser, 'A zone file must contain resource records beyond an SOA'}} =
             parse_result
  end
end
