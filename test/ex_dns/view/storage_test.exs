defmodule ExDns.View.StorageTest do
  @moduledoc """
  Verifies per-view zone storage: same-apex isolation across
  views, longest-suffix find_zone, and the three lookup
  outcomes (`{:ok, ...}`, `{:error, :nxdomain}`, `:miss`).
  """

  use ExUnit.Case, async: false

  alias ExDns.Resource.{A, NS, SOA}
  alias ExDns.View.Storage, as: VS

  setup do
    VS.init()
    VS.clear()
    on_exit(fn -> VS.clear() end)
    :ok
  end

  defp soa(name) do
    %SOA{
      name: name,
      ttl: 60,
      class: :in,
      mname: "ns",
      email: "h",
      serial: 1,
      refresh: 1,
      retry: 1,
      expire: 1,
      minimum: 1
    }
  end

  describe "put_zone + lookup" do
    test "round-trips a single record" do
      VS.put_zone("internal", "example.test", [
        soa("example.test"),
        %A{name: "host.example.test", ttl: 60, class: :in, ipv4: {10, 0, 0, 1}}
      ])

      assert {:ok, "example.test", [%A{ipv4: {10, 0, 0, 1}}]} =
               VS.lookup("internal", "host.example.test", :a)
    end

    test "returns {:error, :nxdomain} when the view hosts the apex but not the qname" do
      VS.put_zone("internal", "example.test", [soa("example.test")])

      assert {:error, :nxdomain} = VS.lookup("internal", "missing.example.test", :a)
    end

    test "returns :miss when the view doesn't host any zone covering qname" do
      VS.put_zone("internal", "internal.test", [soa("internal.test")])

      assert :miss = VS.lookup("internal", "host.other.test", :a)
    end
  end

  describe "view isolation" do
    test "same apex in two views holds different records" do
      VS.put_zone("internal", "example.test", [
        soa("example.test"),
        %A{name: "host.example.test", ttl: 60, class: :in, ipv4: {10, 0, 0, 1}}
      ])

      VS.put_zone("external", "example.test", [
        soa("example.test"),
        %A{name: "host.example.test", ttl: 60, class: :in, ipv4: {198, 51, 100, 7}}
      ])

      assert {:ok, _, [%A{ipv4: {10, 0, 0, 1}}]} =
               VS.lookup("internal", "host.example.test", :a)

      assert {:ok, _, [%A{ipv4: {198, 51, 100, 7}}]} =
               VS.lookup("external", "host.example.test", :a)
    end

    test "delete_zone in one view doesn't touch another" do
      VS.put_zone("internal", "example.test", [soa("example.test")])
      VS.put_zone("external", "example.test", [soa("example.test")])

      :ok = VS.delete_zone("internal", "example.test")

      assert :miss = VS.lookup("internal", "example.test", :soa)
      assert {:ok, _, [%SOA{}]} = VS.lookup("external", "example.test", :soa)
    end

    test "zones/1 lists only apexes in that view" do
      VS.put_zone("internal", "alpha.test", [soa("alpha.test")])
      VS.put_zone("internal", "bravo.test", [soa("bravo.test")])
      VS.put_zone("external", "charlie.test", [soa("charlie.test")])

      assert MapSet.new(VS.zones("internal")) == MapSet.new(["alpha.test", "bravo.test"])
      assert VS.zones("external") == ["charlie.test"]
      assert VS.zones("nonexistent") == []
    end
  end

  describe "find_zone/2" do
    test "longest-suffix match wins" do
      VS.put_zone("v", "example.test", [
        soa("example.test"),
        %NS{name: "example.test", ttl: 60, class: :in, server: "ns.example.test"}
      ])

      VS.put_zone("v", "sub.example.test", [
        soa("sub.example.test"),
        %NS{name: "sub.example.test", ttl: 60, class: :in, server: "ns.sub.example.test"}
      ])

      assert "sub.example.test" = VS.find_zone("v", "host.sub.example.test")
      assert "example.test" = VS.find_zone("v", "host.example.test")
    end

    test "returns nil when no zone covers qname" do
      VS.put_zone("v", "alpha.test", [soa("alpha.test")])
      assert nil == VS.find_zone("v", "host.bravo.test")
    end
  end

  describe "clear/0" do
    test "drops every zone across every view" do
      VS.put_zone("a", "x.test", [soa("x.test")])
      VS.put_zone("b", "y.test", [soa("y.test")])

      VS.clear()

      assert [] = VS.zones("a")
      assert [] = VS.zones("b")
    end
  end
end
