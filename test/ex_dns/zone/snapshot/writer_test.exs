defmodule ExDns.Zone.Snapshot.WriterTest do
  @moduledoc """
  Verifies the debounced snapshot writer GenServer: bursts of
  `request/0` calls coalesce into a single disk write, and
  `write_now/0` bypasses the debounce.
  """

  use ExUnit.Case, async: false

  alias ExDns.Resource.SOA
  alias ExDns.Storage
  alias ExDns.Zone.Snapshot
  alias ExDns.Zone.Snapshot.Writer

  setup do
    Storage.init()

    path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_snapshot_writer_#{System.unique_integer([:positive])}.bin"
      )

    Storage.put_zone("snap-writer.example", [
      %SOA{
        name: "snap-writer.example",
        ttl: 60,
        class: :in,
        mname: "ns",
        email: "h",
        serial: 1,
        refresh: 60,
        retry: 60,
        expire: 60,
        minimum: 60
      }
    ])

    on_exit(fn ->
      Storage.delete_zone("snap-writer.example")
      File.rm(path)
    end)

    {:ok, path: path}
  end

  test "request/0 is a no-op when the writer is not running" do
    refute Process.whereis(Writer)
    assert :ok = Writer.request()
  end

  test "write_now/0 falls back to a direct Snapshot.write when not running",
       %{path: path} do
    refute Process.whereis(Writer)
    previous = Application.get_env(:ex_dns, :zone_snapshot)
    Application.put_env(:ex_dns, :zone_snapshot, path: path, enabled: true)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :zone_snapshot)
        v -> Application.put_env(:ex_dns, :zone_snapshot, v)
      end
    end)

    assert {:ok, %{zones: count}} = Writer.write_now()
    assert count >= 1
    assert File.exists?(path)
  end

  test "burst of request/0 calls produces ONE write", %{path: path} do
    {:ok, pid} = Writer.start_link(path: path, debounce_ms: 100)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    test_pid = self()

    :telemetry.attach(
      "writer-test-#{System.unique_integer([:positive])}",
      [:ex_dns, :zone_snapshot, :write],
      fn _, measurements, metadata, _ ->
        send(test_pid, {:wrote, measurements, metadata})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach("writer-test") end)

    Enum.each(1..10, fn _ -> Writer.request() end)

    # Wait for one debounce window plus a small margin.
    assert_receive {:wrote, %{zones: zones}, %{path: ^path}}, 500
    assert zones >= 1

    # No second write inside another debounce window.
    refute_receive {:wrote, _, _}, 200
  end

  test "write_now/0 bypasses the debounce", %{path: path} do
    {:ok, pid} = Writer.start_link(path: path, debounce_ms: 5_000)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    Writer.request()
    refute File.exists?(path)

    assert {:ok, %{zones: count}} = Writer.write_now()
    assert count >= 1
    assert File.exists?(path)
  end

  test "successful write emits :write telemetry; failures emit :error", %{path: path} do
    test_pid = self()

    :telemetry.attach_many(
      "writer-tel-test-#{System.unique_integer([:positive])}",
      [
        [:ex_dns, :zone_snapshot, :write],
        [:ex_dns, :zone_snapshot, :error]
      ],
      fn event, _measurements, metadata, _ ->
        send(test_pid, {event, metadata})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach("writer-tel-test") end)

    {:ok, ok_pid} = Writer.start_link(path: path, debounce_ms: 50)

    on_exit(fn -> if Process.alive?(ok_pid), do: GenServer.stop(ok_pid) end)

    Writer.request()
    assert_receive {[:ex_dns, :zone_snapshot, :write], %{path: ^path}}, 500

    GenServer.stop(ok_pid)

    # Use /dev/null as a parent directory: it exists as a
    # character device, so mkdir_p inside it fails on every
    # POSIX platform, including macOS (where /proc does not
    # exist and would otherwise be silently created).
    bad_path = "/dev/null/exdns_no_such_dir/snapshot.bin"
    {:ok, bad_pid} = Writer.start_link(path: bad_path, debounce_ms: 50)
    on_exit(fn -> if Process.alive?(bad_pid), do: GenServer.stop(bad_pid) end)

    Writer.request()
    assert_receive {[:ex_dns, :zone_snapshot, :error], %{path: ^bad_path}}, 1_000
  end

  test "configured_path/0 round-trip: snapshot at boot replays the zone",
       %{path: path} do
    {:ok, pid} = Writer.start_link(path: path, debounce_ms: 50)
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    Writer.write_now()

    Storage.delete_zone("snap-writer.example")
    assert {:error, :nxdomain} = Storage.lookup("snap-writer.example", :soa)

    assert {:ok, count} = Snapshot.replay(path)
    assert count >= 1

    assert {:ok, _, [%SOA{name: "snap-writer.example"}]} =
             Storage.lookup("snap-writer.example", :soa)
  end
end
