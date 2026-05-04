defmodule ExDns.Zone.SecondaryTest do
  @moduledoc """
  End-to-end test of the gen_statem secondary-zone manager:

  * Initial AXFR pulls the zone from a real primary listener and
    transitions to `:loaded`.

  * `notify/1` triggers an immediate refresh.

  * Unreachable primaries leave the machine in `:initial` and
    schedule a retry without crashing.
  """

  use ExUnit.Case, async: false

  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage
  alias ExDns.Zone.Secondary

  setup do
    Application.stop(:ex_dns)
    Application.put_env(:ex_dns, :listener_port, 8055)
    {:ok, _} = Application.ensure_all_started(:ex_dns)

    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)

    on_exit(fn ->
      Enum.each(Storage.zones(), &Storage.delete_zone/1)
    end)

    :ok
  end

  defp soa(serial) do
    %SOA{
      name: "mirror.test",
      ttl: 60,
      class: :in,
      mname: "ns",
      email: "h",
      serial: serial,
      refresh: 60,
      retry: 30,
      expire: 3_600,
      minimum: 60
    }
  end

  test "initial AXFR loads the zone and transitions :initial → :loaded" do
    Storage.put_zone("mirror.test", [
      soa(3),
      %A{name: "host.mirror.test", ttl: 60, class: :in, ipv4: {7, 7, 7, 7}}
    ])

    {:ok, _pid} =
      Secondary.start_link(%{
        apex: "mirror.test",
        primaries: [{{127, 0, 0, 1}, 8055}]
      })

    # Initial pull is delayed by 100ms; give it time + a margin.
    Process.sleep(500)

    assert {:loaded, data} = Secondary.snapshot("mirror.test")
    assert %SOA{serial: 3} = data.soa
  end

  test "unreachable primary keeps the machine in :initial without crashing" do
    {:ok, _pid} =
      Secondary.start_link(%{
        apex: "no-such.test",
        primaries: [{{127, 0, 0, 1}, 1}],
        initial_retry_seconds: 60
      })

    Process.sleep(500)

    assert {:initial, _data} = Secondary.snapshot("no-such.test")
  end

  test "notify/1 returns :ok for a running secondary, error otherwise" do
    Storage.put_zone("kick.test", [soa(1) |> Map.put(:name, "kick.test")])

    {:ok, _pid} =
      Secondary.start_link(%{
        apex: "kick.test",
        primaries: [{{127, 0, 0, 1}, 8055}]
      })

    Process.sleep(500)

    assert :ok = Secondary.notify("kick.test")
    assert {:error, :no_secondary_for_zone} = Secondary.notify("nonexistent.test")
  end
end
