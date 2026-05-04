defmodule ExDns.MDNS.ServicesTest do
  @moduledoc """
  Tests for `ExDns.MDNS.Services` — the DNS-SD (RFC 6763) service
  registry. Each registration must publish PTR + SRV + TXT plus the
  meta-service-browser PTR, all in the `local` zone.
  """

  use ExUnit.Case, async: false

  alias ExDns.MDNS.Services
  alias ExDns.Resource.{A, AAAA, PTR, SRV, TXT}
  alias ExDns.Storage

  setup do
    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)

    case Process.whereis(Services) do
      nil -> :ok
      pid -> safe_stop(pid)
    end

    {:ok, _pid} = Services.start_link([])

    on_exit(fn ->
      case Process.whereis(Services) do
        nil -> :ok
        pid -> safe_stop(pid)
      end

      Enum.each(Storage.zones(), &Storage.delete_zone/1)
    end)

    :ok
  end

  defp safe_stop(pid) do
    try do
      GenServer.stop(pid)
    catch
      :exit, _ -> :ok
    end
  end

  describe "register/1" do
    test "publishes PTR + SRV + TXT + meta-browser PTR for one service" do
      :ok =
        Services.register(
          instance: "MyPrinter",
          service: "_http._tcp",
          port: 80,
          target: "myprinter.local",
          txt: ["path=/admin", "color=true"]
        )

      assert {:ok, _, [%PTR{pointer: "MyPrinter._http._tcp.local"}]} =
               Storage.lookup("_http._tcp.local", :ptr)

      assert {:ok, _, [%SRV{port: 80, target: "myprinter.local"}]} =
               Storage.lookup("MyPrinter._http._tcp.local", :srv)

      assert {:ok, _, [%TXT{strings: ["path=/admin", "color=true"]}]} =
               Storage.lookup("MyPrinter._http._tcp.local", :txt)

      assert {:ok, _, [%PTR{pointer: "_http._tcp.local"}]} =
               Storage.lookup("_services._dns-sd._udp.local", :ptr)
    end

    test "publishes an A record at the target when :address is supplied" do
      :ok =
        Services.register(
          instance: "DiscoBox",
          service: "_disco._udp",
          port: 6789,
          target: "discobox.local",
          address: {192, 168, 1, 50}
        )

      assert {:ok, _, [%A{ipv4: {192, 168, 1, 50}}]} =
               Storage.lookup("discobox.local", :a)
    end

    test "publishes an AAAA record at the target when :address is IPv6" do
      :ok =
        Services.register(
          instance: "v6thing",
          service: "_test._tcp",
          port: 1,
          target: "v6thing.local",
          address: {0xFE80, 0, 0, 0, 0, 0, 0, 1}
        )

      assert {:ok, _, [%AAAA{ipv6: {0xFE80, 0, 0, 0, 0, 0, 0, 1}}]} =
               Storage.lookup("v6thing.local", :aaaa)
    end

    test "two services on the same type produce two PTR answers + their own SRV/TXT" do
      :ok = Services.register(instance: "A", service: "_http._tcp", port: 80, target: "a.local")
      :ok = Services.register(instance: "B", service: "_http._tcp", port: 8080, target: "b.local")

      {:ok, _, ptrs} = Storage.lookup("_http._tcp.local", :ptr)
      pointers = Enum.map(ptrs, & &1.pointer)
      assert "A._http._tcp.local" in pointers
      assert "B._http._tcp.local" in pointers

      assert {:ok, _, [%SRV{port: 80}]} = Storage.lookup("A._http._tcp.local", :srv)
      assert {:ok, _, [%SRV{port: 8080}]} = Storage.lookup("B._http._tcp.local", :srv)
    end

    test "two services of different types each appear in the meta-browser" do
      :ok = Services.register(instance: "X", service: "_http._tcp", port: 80, target: "x.local")
      :ok = Services.register(instance: "Y", service: "_ssh._tcp", port: 22, target: "y.local")

      {:ok, _, ptrs} = Storage.lookup("_services._dns-sd._udp.local", :ptr)
      pointers = Enum.map(ptrs, & &1.pointer) |> MapSet.new()
      assert "_http._tcp.local" in pointers
      assert "_ssh._tcp.local" in pointers
    end

    test "default target is derived from the instance name" do
      :ok = Services.register(instance: "AutoTarget", service: "_http._tcp", port: 80)

      {:ok, _, [%SRV{target: target}]} = Storage.lookup("AutoTarget._http._tcp.local", :srv)
      assert target == "AutoTarget.local"
    end
  end

  describe "unregister/2" do
    test "removes a service while leaving siblings intact" do
      :ok = Services.register(instance: "Keep", service: "_http._tcp", port: 80, target: "k.local")
      :ok = Services.register(instance: "Drop", service: "_http._tcp", port: 90, target: "d.local")

      :ok = Services.unregister("Drop", "_http._tcp")

      assert {:error, :nxdomain} = Storage.lookup("Drop._http._tcp.local", :srv)
      assert {:ok, _, [%SRV{port: 80}]} = Storage.lookup("Keep._http._tcp.local", :srv)

      {:ok, _, ptrs} = Storage.lookup("_http._tcp.local", :ptr)
      pointers = Enum.map(ptrs, & &1.pointer)
      assert pointers == ["Keep._http._tcp.local"]
    end

    test "is idempotent on unknown services" do
      :ok = Services.unregister("nope", "_nope._udp")
    end
  end

  describe "list/0" do
    test "returns the current registry" do
      :ok = Services.register(instance: "One", service: "_http._tcp", port: 80, target: "o.local")
      assert [service] = Services.list()
      assert service.instance == "One"
      assert service.port == 80
    end
  end
end
