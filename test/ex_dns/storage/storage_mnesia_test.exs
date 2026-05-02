defmodule ExDns.Storage.MnesiaTest do
  use ExUnit.Case, async: false

  alias ExDns.Storage.Mnesia, as: Storage
  alias ExDns.Resource.{A, AAAA, NS, MX, SOA}

  setup_all do
    Storage.init()
    :ok
  end

  setup do
    Enum.each(Storage.zones(), &Storage.delete_zone/1)
    on_exit(fn -> Enum.each(Storage.zones(), &Storage.delete_zone/1) end)
    :ok
  end

  describe "put_zone/2 + lookup/2" do
    test "round-trips a single A record" do
      Storage.put_zone("example.com", [
        %A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}
      ])

      assert {:ok, "example.com", [%A{ipv4: {192, 0, 2, 1}}]} =
               Storage.lookup("example.com", :a)
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
  end

  describe "lookup/2 NXDOMAIN vs NODATA semantics" do
    test "returns NODATA when name exists but type does not" do
      Storage.put_zone("example.com", [
        %A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}
      ])

      assert {:ok, "example.com", []} = Storage.lookup("example.com", :aaaa)
    end

    test "returns NXDOMAIN for unknown name in known zone" do
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
          email: "h.example.com",
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
      assert Storage.find_zone("example.com") == "example.com"
      assert Storage.find_zone("nope.test") == nil
    end
  end

  describe "lookup_any/1, lookup_wildcard/2, find_delegation/1, dump_zone/1" do
    test "lookup_any returns every type at the name" do
      Storage.put_zone("example.com", [
        %A{name: "host.example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}},
        %AAAA{name: "host.example.com", ttl: 60, class: :in, ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}},
        %MX{name: "host.example.com", ttl: 60, class: :in, priority: 10, server: "mail.example.com"}
      ])

      assert {:ok, _, records} = Storage.lookup_any("host.example.com")
      types = Enum.map(records, & &1.__struct__)
      assert ExDns.Resource.A in types
      assert ExDns.Resource.AAAA in types
      assert ExDns.Resource.MX in types
    end

    test "lookup_wildcard matches *.parent" do
      Storage.put_zone("wild.test", [
        %A{name: "*.wild.test", ttl: 60, class: :in, ipv4: {198, 51, 100, 99}}
      ])

      assert {:ok, "wild.test", [_record]} = Storage.lookup_wildcard("anything.wild.test", :a)
    end

    test "find_delegation walks ancestors and returns NS records" do
      Storage.put_zone("parent.test", [
        %SOA{
          name: "parent.test",
          ttl: 86_400,
          class: :in,
          mname: "ns.parent.test",
          email: "admin.parent.test",
          serial: 1,
          refresh: 7200,
          retry: 3600,
          expire: 1_209_600,
          minimum: 3600
        },
        %NS{name: "sub.parent.test", ttl: 86_400, class: :in, server: "ns1.sub.parent.test"}
      ])

      assert {:ok, "parent.test", "sub.parent.test", [%NS{}]} =
               Storage.find_delegation("host.sub.parent.test")
    end

    test "dump_zone returns SOA first, then the rest" do
      Storage.put_zone("xfer.test", [
        %SOA{
          name: "xfer.test",
          ttl: 86_400,
          class: :in,
          mname: "ns.xfer.test",
          email: "admin.xfer.test",
          serial: 1,
          refresh: 7200,
          retry: 3600,
          expire: 1_209_600,
          minimum: 3600
        },
        %A{name: "xfer.test", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}
      ])

      assert {:ok, [%SOA{} | rest]} = Storage.dump_zone("xfer.test")
      assert Enum.any?(rest, &match?(%A{}, &1))
    end
  end

  describe "delete_zone/1" do
    test "removes every record and the apex from the index" do
      Storage.put_zone("example.com", [
        %A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}
      ])

      Storage.delete_zone("example.com")
      refute "example.com" in Storage.zones()
      assert {:error, :nxdomain} = Storage.lookup("example.com", :a)
    end
  end
end
