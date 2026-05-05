defmodule ExDns.Zone.SnapshotTest do
  @moduledoc """
  Verifies the pure zone-snapshot reader/writer/replayer.
  Storage state is mutated and reset between tests, so this
  suite runs `async: false`.
  """

  use ExUnit.Case, async: false

  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage
  alias ExDns.Zone.Snapshot

  doctest Snapshot

  setup do
    Storage.init()

    # Clean up any zones the suite may leave behind so it
    # doesn't perturb other tests.
    on_exit(fn ->
      ~w(snap-test.example snap-rt.example snap-empty.example)
      |> Enum.each(&Storage.delete_zone/1)
    end)

    :ok
  end

  defp tmp_path(label) do
    Path.join(
      System.tmp_dir!(),
      "ex_dns_snapshot_#{label}_#{System.unique_integer([:positive])}.bin"
    )
  end

  defp soa(apex) do
    %SOA{
      name: apex,
      ttl: 60,
      class: :in,
      mname: "ns.#{apex}",
      email: "hostmaster.#{apex}",
      serial: 1,
      refresh: 60,
      retry: 60,
      expire: 60,
      minimum: 60
    }
  end

  defp install_zone(apex, extra_records \\ []) do
    Storage.put_zone(apex, [soa(apex) | extra_records])
  end

  describe "write/1 + read/1 round-trip" do
    test "captures every zone in storage" do
      install_zone("snap-test.example", [
        %A{name: "a.snap-test.example", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}
      ])

      path = tmp_path("rt")

      try do
        assert {:ok, %{zones: count, bytes: bytes}} = Snapshot.write(path)
        assert count >= 1
        assert bytes > 0

        assert {:ok, %{written_at_unix: at, zones: zones}} = Snapshot.read(path)
        assert is_integer(at)
        assert Map.has_key?(zones, "snap-test.example")
        records = Map.fetch!(zones, "snap-test.example")
        assert Enum.any?(records, &match?(%A{ipv4: {1, 2, 3, 4}}, &1))
      after
        File.rm(path)
      end
    end
  end

  describe "read/1 error shapes" do
    test "missing file → {:error, :enoent}" do
      assert {:error, :enoent} = Snapshot.read("/nope/snapshot/nowhere.bin")
    end

    test "wrong magic bytes → {:error, :bad_magic}" do
      path = tmp_path("badmagic")
      File.write!(path, "not a snapshot")
      try do
        assert {:error, :bad_magic} = Snapshot.read(path)
      after
        File.rm(path)
      end
    end

    test "unknown version byte → {:error, {:bad_version, n}}" do
      path = tmp_path("badversion")
      # Magic + version byte 99 + some payload bytes.
      File.write!(path, "EXDNSZSNAP\0" <> <<99>> <> "garbage")
      try do
        assert {:error, {:bad_version, 99}} = Snapshot.read(path)
      after
        File.rm(path)
      end
    end

    test "right magic + version but corrupt body → {:error, :corrupt}" do
      path = tmp_path("corrupt")
      File.write!(path, "EXDNSZSNAP\0" <> <<1>> <> <<255, 255, 255>>)
      try do
        assert {:error, :corrupt} = Snapshot.read(path)
      after
        File.rm(path)
      end
    end
  end

  describe "replay/1" do
    test "installs every zone in the snapshot" do
      install_zone("snap-rt.example", [
        %A{name: "host.snap-rt.example", ttl: 30, class: :in, ipv4: {9, 9, 9, 9}}
      ])

      path = tmp_path("replay")

      try do
        assert {:ok, _} = Snapshot.write(path)

        # Wipe storage; replay should put the zone back.
        Storage.delete_zone("snap-rt.example")
        assert {:error, :nxdomain} = Storage.lookup("host.snap-rt.example", :a)

        assert {:ok, count} = Snapshot.replay(path)
        assert count >= 1
        assert {:ok, _, [%A{ipv4: {9, 9, 9, 9}}]} =
                 Storage.lookup("host.snap-rt.example", :a)
      after
        File.rm(path)
      end
    end

    test "missing file is reported as :enoent (caller treats as no-op)" do
      assert {:error, :enoent} = Snapshot.replay("/nowhere/snap.bin")
    end
  end

  describe "configured_path/0 + enabled?/0" do
    test "configured_path returns the configured value or a tmp default" do
      previous = Application.get_env(:ex_dns, :zone_snapshot)

      try do
        Application.put_env(:ex_dns, :zone_snapshot, path: "/etc/snap.bin", enabled: true)
        assert "/etc/snap.bin" = Snapshot.configured_path()
        assert Snapshot.enabled?()

        Application.delete_env(:ex_dns, :zone_snapshot)
        assert Snapshot.configured_path() =~ "ex_dns_zone_snapshot"
        refute Snapshot.enabled?()
      after
        case previous do
          nil -> Application.delete_env(:ex_dns, :zone_snapshot)
          v -> Application.put_env(:ex_dns, :zone_snapshot, v)
        end
      end
    end
  end
end
