defmodule ExDns.BlackHole.Storage.SQLiteTest do
  @moduledoc """
  Round-trip tests for the SQLite-backed BlackHole storage
  adapter — schema creation, CRUD on each table, query-log
  pagination, and the kv store.
  """

  use ExUnit.Case, async: false

  alias ExDns.BlackHole.Storage.SQLite

  setup do
    path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_blackhole_sqlite_#{System.unique_integer([:positive])}.db"
      )

    {:ok, state} = SQLite.init(path: path)

    on_exit(fn ->
      File.rm(path)
      File.rm(path <> "-wal")
      File.rm(path <> "-shm")
    end)

    {:ok, state: state}
  end

  describe "blocklists" do
    test "round-trip", %{state: state} do
      {:ok, %{"id" => id}} =
        SQLite.put_blocklist(state, %{"url" => "https://x", "name" => "x", "enabled" => true})

      [row] = SQLite.list_blocklists(state)
      assert row["id"] == id
      assert row["url"] == "https://x"
      assert row["enabled"] == true

      :ok = SQLite.delete_blocklist(state, id)
      assert [] = SQLite.list_blocklists(state)
    end
  end

  describe "allowlist + denylist" do
    test "allowlist round-trip", %{state: state} do
      {:ok, _} = SQLite.put_allow(state, %{"domain" => "ok.example", "comment" => "ours"})
      [%{"domain" => "ok.example", "comment" => "ours"}] = SQLite.list_allow(state)

      :ok = SQLite.delete_allow(state, "ok.example")
      assert [] = SQLite.list_allow(state)
    end

    test "denylist round-trip", %{state: state} do
      {:ok, _} = SQLite.put_deny(state, %{"domain" => "bad.example"})
      [%{"domain" => "bad.example"}] = SQLite.list_deny(state)
      :ok = SQLite.delete_deny(state, "bad.example")
      assert [] = SQLite.list_deny(state)
    end
  end

  describe "groups" do
    test "stores cidrs + blocklist_ids as JSON arrays", %{state: state} do
      {:ok, %{"id" => id}} =
        SQLite.put_group(state, %{
          "name" => "home",
          "cidrs" => ["192.168.1.0/24"],
          "blocklist_ids" => ["abc", "def"]
        })

      [row] = SQLite.list_groups(state)
      assert row["id"] == id
      assert row["cidrs"] == ["192.168.1.0/24"]
      assert row["blocklist_ids"] == ["abc", "def"]
    end
  end

  describe "query_log" do
    test "append + read paginated newest-first", %{state: state} do
      now = System.os_time(:nanosecond)

      Enum.each(0..4, fn i ->
        :ok =
          SQLite.append_query_log(state, %{
            "ts_ns" => now + i,
            "client_ip" => "1.2.3.4",
            "qname" => "x#{i}.test",
            "qtype" => :a,
            "decision" => :allow
          })
      end)

      page = SQLite.read_query_log(state, %{limit: 3})
      assert length(page.rows) == 3
      [first | _] = page.rows
      # newest first
      assert first["qname"] == "x4.test"
      assert page.next_cursor != nil

      page2 = SQLite.read_query_log(state, %{limit: 3, cursor: page.next_cursor})
      assert length(page2.rows) <= 3
      assert page2.next_cursor == nil
    end

    test "truncate clears the log", %{state: state} do
      :ok =
        SQLite.append_query_log(state, %{
          "ts_ns" => System.os_time(:nanosecond),
          "client_ip" => "1.2.3.4",
          "qname" => "x.test",
          "qtype" => :a,
          "decision" => :allow
        })

      :ok = SQLite.truncate_query_log(state)
      assert %{rows: [], next_cursor: nil} = SQLite.read_query_log(state, %{})
    end
  end

  describe "kv" do
    test "round-trips arbitrary terms", %{state: state} do
      :ok = SQLite.put_kv(state, "stats", %{queries: 99, blocked: 7})
      assert {:ok, %{queries: 99, blocked: 7}} = SQLite.get_kv(state, "stats")
    end

    test ":error for unknown key", %{state: state} do
      assert :error = SQLite.get_kv(state, "missing")
    end
  end
end
