defmodule ExDns.Storage.ETSTest do
  use ExUnit.Case, async: false

  alias ExDns.Storage.ETS, as: Storage
  alias ExDns.Resource.{A, AAAA, NS, MX, SOA}

  setup do
    Storage.init()
    on_exit(fn -> Enum.each(Storage.zones(), &Storage.delete_zone/1) end)
    :ok
  end

  describe "put_zone/2 + lookup/2" do
    test "looks up an A record by name and type" do
      Storage.put_zone("example.com", [
        %A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}
      ])

      assert {:ok, "example.com", [record]} = Storage.lookup("example.com", :a)
      assert record.ipv4 == {192, 0, 2, 1}
    end

    test "groups multiple records of the same name+type into one RRset" do
      Storage.put_zone("example.com", [
        %A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}},
        %A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 2}}
      ])

      assert {:ok, _, records} = Storage.lookup("example.com", :a)
      assert length(records) == 2
    end

    test "is case-insensitive on names" do
      Storage.put_zone("Example.COM", [
        %A{name: "WWW.Example.COM", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}
      ])

      assert {:ok, _, [_record]} = Storage.lookup("www.example.com", :a)
    end

    test "tolerates trailing dots in apex and queries" do
      Storage.put_zone("example.com.", [
        %A{name: "example.com.", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}
      ])

      assert {:ok, _, [_record]} = Storage.lookup("example.com.", :a)
    end
  end

  describe "lookup/2 NXDOMAIN vs NODATA semantics" do
    test "returns :nxdomain when no zone covers the query name" do
      Storage.put_zone("example.com", [
        %A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}
      ])

      assert {:error, :nxdomain} = Storage.lookup("nope.test", :a)
    end

    test "returns NODATA (empty list) when name exists but type does not" do
      Storage.put_zone("example.com", [
        %A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}
      ])

      assert {:ok, "example.com", []} = Storage.lookup("example.com", :aaaa)
    end

    test "returns NXDOMAIN for unknown names within a known zone" do
      Storage.put_zone("example.com", [
        %A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}
      ])

      assert {:error, :nxdomain} = Storage.lookup("missing.example.com", :a)
    end
  end

  describe "find_zone/1" do
    test "selects the longest-suffix matching apex" do
      Storage.put_zone("example.com", [
        %SOA{
          name: "example.com",
          ttl: 86_400,
          class: :in,
          mname: "ns.example.com",
          email: "hostmaster.example.com",
          serial: 1,
          refresh: 7200,
          retry: 3600,
          expire: 1_209_600,
          minimum: 3600
        }
      ])

      Storage.put_zone("host.example.com", [
        %A{name: "host.example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 9}}
      ])

      assert Storage.find_zone("anything.host.example.com") == "host.example.com"
      assert Storage.find_zone("anything.example.com") == "example.com"
      assert Storage.find_zone("not.in.scope") == nil
    end
  end

  describe "delete_zone/1 + zones/0" do
    test "round-trips a zone in/out and reflects in zones/0" do
      Storage.put_zone("example.com", [
        %NS{name: "example.com", ttl: 86_400, class: :in, server: "ns1.example.com"},
        %MX{name: "example.com", ttl: 3600, class: :in, priority: 10, server: "mail.example.com"},
        %AAAA{name: "ipv6.example.com", ttl: 60, class: :in, ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}}
      ])

      assert "example.com" in Storage.zones()
      Storage.delete_zone("example.com")
      refute "example.com" in Storage.zones()
      assert {:error, :nxdomain} = Storage.lookup("example.com", :ns)
    end
  end
end
