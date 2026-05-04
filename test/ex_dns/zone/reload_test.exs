defmodule ExDns.Zone.ReloadTest do
  @moduledoc """
  Verifies hot-reload behaviour: rewriting a configured zone file
  and calling `reload_all/0` picks up the new contents (including
  a serial bump that triggers the IXFR journal).
  """

  use ExUnit.Case, async: false

  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage
  alias ExDns.Zone.{Journal, Reload}

  setup do
    Storage.init()
    Journal.clear()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)

    previous_zones = Application.get_env(:ex_dns, :zones)

    on_exit(fn ->
      case previous_zones do
        nil -> Application.delete_env(:ex_dns, :zones)
        other -> Application.put_env(:ex_dns, :zones, other)
      end

      Enum.each(Storage.zones(), &Storage.delete_zone/1)
    end)

    :ok
  end

  defp write_zone(path, serial, ipv4) do
    contents = """
    $ORIGIN reload.test.
    $TTL 3600
    @  IN SOA  ns admin (
                  #{serial}
                  3600
                  600
                  86400
                  60
                )
       IN NS   ns
    ns IN A   192.0.2.1
    host IN A #{:inet.ntoa(ipv4)}
    """

    File.write!(path, contents)
  end

  test "reload_all/0 picks up a new SOA and a changed A record" do
    path = Path.join(System.tmp_dir!(), "exdns-reload-test-#{System.unique_integer([:positive])}.zone")
    on_exit(fn -> File.rm(path) end)

    write_zone(path, 1, {10, 0, 0, 1})
    Application.put_env(:ex_dns, :zones, [path])

    # Initial load via reload_all (acts like the application's
    # autoload).
    assert {1, 0} = Reload.reload_all()

    {:ok, _, [%A{ipv4: {10, 0, 0, 1}}]} = Storage.lookup("host.reload.test", :a)

    # Bump serial + change A.
    write_zone(path, 2, {10, 0, 0, 99})

    assert {1, 0} = Reload.reload_all()

    {:ok, _, [%A{ipv4: {10, 0, 0, 99}}]} = Storage.lookup("host.reload.test", :a)

    # Journal records the 1→2 transition.
    [entry] = Journal.since("reload.test", 1)
    assert entry.from_serial == 1
    assert entry.to_serial == 2
  end

  test "reload_all/0 reports failures without aborting other zones" do
    good_path = Path.join(System.tmp_dir!(), "exdns-good-#{System.unique_integer([:positive])}.zone")
    bad_path = Path.join(System.tmp_dir!(), "exdns-bad-#{System.unique_integer([:positive])}.zone")
    on_exit(fn -> File.rm(good_path); File.rm(bad_path) end)

    write_zone(good_path, 1, {10, 0, 0, 1})
    File.write!(bad_path, "this is not a valid zone file at all")

    Application.put_env(:ex_dns, :zones, [good_path, bad_path])

    assert {1, 1} = Reload.reload_all()

    # The good zone made it in despite the bad one failing.
    {:ok, _, [%SOA{}]} = Storage.lookup("reload.test", :soa)
  end

  test "reload telemetry stop event reports loaded + failed counts" do
    path = Path.join(System.tmp_dir!(), "exdns-tel-#{System.unique_integer([:positive])}.zone")
    on_exit(fn -> File.rm(path) end)

    write_zone(path, 1, {10, 0, 0, 1})
    Application.put_env(:ex_dns, :zones, [path])

    test_pid = self()

    :telemetry.attach(
      "reload-test",
      [:ex_dns, :zone, :reload, :stop],
      fn _, measurements, _, _ -> send(test_pid, {:reload, measurements}) end,
      %{}
    )

    on_exit(fn -> :telemetry.detach("reload-test") end)

    Reload.reload_all()

    assert_receive {:reload, %{loaded: 1, failed: 0}}
  end
end
