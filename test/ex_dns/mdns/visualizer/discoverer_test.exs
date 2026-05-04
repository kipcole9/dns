defmodule ExDns.MDNS.Visualizer.DiscovererTest do
  @moduledoc """
  End-to-end test for the visualizer's discoverer. Boots both the
  mDNS responder and the discoverer on a non-standard port, registers
  one service, forces a refresh, and asserts the snapshot reflects the
  service.

  The QU bit on outbound queries makes responses unicast back to the
  discoverer's ephemeral source port, so loopback unicast is enough —
  no real multicast routing required.
  """

  use ExUnit.Case, async: false

  alias ExDns.MDNS.Services
  alias ExDns.MDNS.Visualizer.Discoverer

  @port 8255

  setup_all do
    previous = Application.get_env(:ex_dns, :mdns)

    Application.stop(:ex_dns)

    Application.put_env(:ex_dns, :mdns,
      enabled: true,
      port: @port,
      multicast_ip: {127, 0, 0, 1},
      interface: {127, 0, 0, 1},
      multicast_loop: true
    )

    {:ok, _} = Application.ensure_all_started(:ex_dns)

    {:ok, _} =
      Discoverer.start_link(
        interval: 60_000,
        listen_window: 500,
        multicast_ip: {127, 0, 0, 1},
        port: @port
      )

    Services.register(
      instance: "DiscDemo",
      service: "_demo._tcp",
      port: 9090,
      target: "discdemo.local",
      address: {127, 0, 0, 1},
      txt: ["mode=demo"]
    )

    on_exit(fn ->
      case Process.whereis(Discoverer) do
        nil -> :ok
        pid -> safe_stop(pid)
      end

      Application.stop(:ex_dns)

      case previous do
        nil -> Application.delete_env(:ex_dns, :mdns)
        value -> Application.put_env(:ex_dns, :mdns, value)
      end
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

  test "discoverer observes a registered service via the meta-browser → instance → SRV/TXT/A flow" do
    Discoverer.refresh_now()
    snapshot = Discoverer.snapshot()

    assert "_demo._tcp.local" in snapshot.types
    assert Map.has_key?(snapshot.services, "_demo._tcp.local")

    instances = snapshot.services["_demo._tcp.local"]
    assert {_instance_name, details} = Enum.find(instances, fn {_, _d} -> true end)
    assert details.srv.port == 9090
    assert details.srv.target == "discdemo.local"
    assert details.txt.strings == ["mode=demo"]
    assert {127, 0, 0, 1} in details.addresses
  end
end
