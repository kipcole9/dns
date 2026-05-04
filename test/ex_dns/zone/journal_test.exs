defmodule ExDns.Zone.JournalTest do
  @moduledoc """
  Verifies the IXFR journal records deltas correctly, retrieves them
  in serial order, and integrates with `ExDns.Storage.put_zone/2`.
  """

  use ExUnit.Case, async: false

  alias ExDns.Zone.Journal
  alias ExDns.Zone.Journal.Entry
  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage

  doctest Journal

  setup do
    Storage.init()
    Journal.clear()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)
    on_exit(fn -> Enum.each(Storage.zones(), &Storage.delete_zone/1) end)
    :ok
  end

  defp soa(serial) do
    %SOA{
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

  defp a(name, ip) do
    %A{name: name, ttl: 60, class: :in, ipv4: ip}
  end

  test "record/3 captures serial advance and per-record diff" do
    old = [soa(1), a("host.example.test", {1, 1, 1, 1})]
    new = [soa(2), a("host.example.test", {1, 1, 1, 2})]

    assert {:ok, entry} = Journal.record("example.test", old, new)
    assert %Entry{from_serial: 1, to_serial: 2} = entry
    assert a("host.example.test", {1, 1, 1, 1}) in entry.removed
    assert a("host.example.test", {1, 1, 1, 2}) in entry.added
  end

  test "record/3 returns :no_change when serials match" do
    records = [soa(5), a("host.example.test", {1, 1, 1, 1})]
    assert :no_change = Journal.record("example.test", records, records)
  end

  test "record/3 rejects a backwards serial" do
    old = [soa(10)]
    new = [soa(9)]
    assert {:error, :serial_did_not_advance} = Journal.record("example.test", old, new)
  end

  test "record/3 honours RFC 1982 wraparound" do
    # 0xFFFFFFFE → 0x00000001 is a forward advance by 3 modulo 2^32.
    old = [soa(0xFFFFFFFE)]
    new = [soa(1)]
    assert {:ok, %Entry{from_serial: 0xFFFFFFFE, to_serial: 1}} =
             Journal.record("example.test", old, new)
  end

  test "since/2 returns deltas in serial order" do
    Journal.record("example.test", [soa(1)], [soa(2), a("a.example.test", {1, 1, 1, 1})])

    Journal.record(
      "example.test",
      [soa(2), a("a.example.test", {1, 1, 1, 1})],
      [soa(3), a("a.example.test", {1, 1, 1, 1}), a("b.example.test", {2, 2, 2, 2})]
    )

    entries = Journal.since("example.test", 1)
    assert length(entries) == 2
    assert [%Entry{to_serial: 2}, %Entry{to_serial: 3}] = entries
  end

  test "since/2 filters out entries the client already has" do
    Journal.record("example.test", [soa(1)], [soa(2)])
    Journal.record("example.test", [soa(2)], [soa(3)])

    # Client has serial 2 — only the 2→3 delta should be returned.
    assert [%Entry{from_serial: 2, to_serial: 3}] = Journal.since("example.test", 2)
  end

  test "latest_serial/1 returns the highest recorded to_serial" do
    Journal.record("example.test", [soa(1)], [soa(2)])
    Journal.record("example.test", [soa(2)], [soa(7)])

    assert Journal.latest_serial("example.test") == 7
    assert Journal.latest_serial("nonexistent") == nil
  end

  test "Storage.put_zone/2 records a journal entry on serial advance" do
    Storage.put_zone("example.test", [soa(1), a("host.example.test", {1, 1, 1, 1})])

    Storage.put_zone("example.test", [soa(2), a("host.example.test", {2, 2, 2, 2})])

    [entry] = Journal.since("example.test", 1)
    assert entry.from_serial == 1
    assert entry.to_serial == 2
    assert a("host.example.test", {1, 1, 1, 1}) in entry.removed
    assert a("host.example.test", {2, 2, 2, 2}) in entry.added
  end

  test "Storage.put_zone/2 records nothing on initial load" do
    Storage.put_zone("example.test", [soa(1)])
    assert Journal.since("example.test", 0) == []
  end

  test "case-insensitive apex matching" do
    Journal.record("Example.Test", [soa(1)], [soa(2)])
    assert [_] = Journal.since("EXAMPLE.test", 1)
    assert Journal.latest_serial("example.test") == 2
  end
end
