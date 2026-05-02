defmodule ExDns.ZoneTest do
  use ExUnit.Case, async: false

  alias ExDns.Storage.ETS, as: Storage
  alias ExDns.Zone

  setup do
    Storage.init()
    on_exit(fn -> Enum.each(Storage.zones(), &Storage.delete_zone/1) end)
    :ok
  end

  describe "load_file/1" do
    test "loads test_zone_file_2.txt and registers records in storage" do
      assert {:ok, %Zone{}} = Zone.load_file("test/support/test_zone_file_2.txt")

      assert "example.com" in Storage.zones()
      assert {:ok, "example.com", soa_records} = Storage.lookup("example.com", :soa)
      assert length(soa_records) >= 1
      assert {:ok, "example.com", a_records} = Storage.lookup("example.com", :a)
      assert Enum.any?(a_records, fn record -> record.ipv4 == {192, 0, 2, 1} end)
    end
  end

  describe "load_string/1" do
    test "parses a small zone string and stores it" do
      zone_text = """
      $ORIGIN example.test.
      $TTL 3600
      example.test. IN SOA ns.example.test. admin.example.test. ( 1 7200 3600 1209600 3600 )
      example.test. IN NS  ns.example.test.
      example.test. IN A   192.0.2.1
      ns            IN A   192.0.2.53
      """

      assert {:ok, %Zone{}} = Zone.load_string(zone_text)
      assert "example.test" in Storage.zones()
      assert {:ok, _, [%ExDns.Resource.A{ipv4: {192, 0, 2, 1}}]} =
               Storage.lookup("example.test", :a)

      assert {:ok, _, [%ExDns.Resource.A{ipv4: {192, 0, 2, 53}}]} =
               Storage.lookup("ns.example.test", :a)
    end
  end
end
