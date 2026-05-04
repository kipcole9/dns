defmodule ExDns.Zone.Journal.Storage.DETSTest do
  @moduledoc """
  Verifies the DETS-backed journal storage persists entries across
  process restarts: insert with one BEAM-internal "process", close,
  re-init, read back.
  """

  use ExUnit.Case, async: false

  alias ExDns.Zone.Journal
  alias ExDns.Zone.Journal.Entry
  alias ExDns.Zone.Journal.Storage.DETS

  setup do
    previous = Application.get_env(:ex_dns, :journal)
    path = Path.join(System.tmp_dir!(), "exdns-journal-test-#{System.unique_integer([:positive])}.dets")

    Application.put_env(:ex_dns, :journal,
      backend: DETS,
      path: path
    )

    DETS.clear()

    on_exit(fn ->
      DETS.close()
      File.rm(path)

      case previous do
        nil -> Application.delete_env(:ex_dns, :journal)
        other -> Application.put_env(:ex_dns, :journal, other)
      end
    end)

    {:ok, path: path}
  end

  defp soa(serial) do
    %ExDns.Resource.SOA{
      name: "example.test",
      ttl: 60,
      class: :in,
      mname: "ns",
      email: "h",
      serial: serial,
      refresh: 1,
      retry: 1,
      expire: 1,
      minimum: 1
    }
  end

  test "Journal.record/3 persists through DETS backend" do
    assert {:ok, _entry} = Journal.record("example.test", [soa(1)], [soa(2)])

    assert [%Entry{from_serial: 1, to_serial: 2}] = Journal.since("example.test", 0)
    assert Journal.latest_serial("example.test") == 2
  end

  test "entries survive DETS close + re-open", %{path: path} do
    # Write an entry.
    assert {:ok, _} = Journal.record("example.test", [soa(5)], [soa(6)])

    # Close the DETS handle so the file is consistent on disk.
    :ok = DETS.close()

    # Re-init the table from the same file (simulating an
    # application restart).
    Application.put_env(:ex_dns, :journal, backend: DETS, path: path)
    Journal.init()

    assert [%Entry{from_serial: 5, to_serial: 6}] = Journal.since("example.test", 0)
    assert Journal.latest_serial("example.test") == 6
  end

  test "clear/0 removes every entry" do
    assert {:ok, _} = Journal.record("example.test", [soa(1)], [soa(2)])
    assert [_] = Journal.since("example.test", 0)

    DETS.clear()

    assert [] = Journal.since("example.test", 0)
  end
end
