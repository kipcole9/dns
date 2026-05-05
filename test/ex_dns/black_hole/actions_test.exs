defmodule ExDns.BlackHole.ActionsTest do
  @moduledoc """
  Tests for the BlackHole plugin's handle_action/2 callbacks
  — covering blocklist / allow / deny / group CRUD plus
  query-log clear.
  """

  use ExUnit.Case, async: false

  alias ExDns.BlackHole.{Plugin, Storage}
  alias ExDns.Plugin.Registry

  setup do
    Registry.clear()

    path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_blackhole_actions_#{System.unique_integer([:positive])}.db"
      )

    previous = Application.get_env(:ex_dns, :black_hole)

    Application.put_env(:ex_dns, :black_hole,
      storage: {ExDns.BlackHole.Storage.SQLite, [path: path]}
    )

    :ok = Storage.init()
    :ok = Registry.register(Plugin)

    on_exit(fn ->
      Registry.clear()
      File.rm(path)
      File.rm(path <> "-wal")
      File.rm(path <> "-shm")

      case previous do
        nil -> Application.delete_env(:ex_dns, :black_hole)
        v -> Application.put_env(:ex_dns, :black_hole, v)
      end
    end)

    :ok
  end

  test "add + remove blocklist" do
    {:ok, %{"id" => id}} =
      Plugin.handle_action("add_blocklist", %{"url" => "https://x", "name" => "x"})

    assert [%{"id" => ^id}] = Storage.list_blocklists()

    {:ok, %{"id" => ^id}} = Plugin.handle_action("remove_blocklist", %{"id" => id})
    assert [] = Storage.list_blocklists()
  end

  test "set_blocklist_enabled toggles without removing" do
    {:ok, %{"id" => id}} =
      Plugin.handle_action("add_blocklist", %{"url" => "https://x", "enabled" => true})

    {:ok, %{"enabled" => false}} =
      Plugin.handle_action("set_blocklist_enabled", %{"id" => id, "enabled" => false})

    [row] = Storage.list_blocklists()
    assert row["enabled"] == false
  end

  test "add + remove allowlist entry" do
    {:ok, _} = Plugin.handle_action("add_allowlist", %{"domain" => "OK.example."})
    [%{"domain" => "ok.example"}] = Storage.list_allow()

    {:ok, _} = Plugin.handle_action("remove_allowlist", %{"domain" => "ok.example"})
    assert [] = Storage.list_allow()
  end

  test "add + remove denylist entry" do
    {:ok, _} = Plugin.handle_action("add_denylist", %{"domain" => "ads.example"})
    [%{"domain" => "ads.example"}] = Storage.list_deny()

    {:ok, _} = Plugin.handle_action("remove_denylist", %{"domain" => "ads.example"})
    assert [] = Storage.list_deny()
  end

  test "add_group calls update_routes" do
    {:ok, %{"id" => id}} =
      Plugin.handle_action("add_group", %{
        "name" => "home",
        "cidrs" => ["192.168.1.0/24"],
        "blocklist_ids" => []
      })

    assert [%{"id" => ^id, "cidrs" => ["192.168.1.0/24"]}] = Storage.list_groups()
  end

  test "clear_query_log truncates" do
    :ok =
      Storage.append_query_log(%{
        "ts_ns" => System.os_time(:nanosecond),
        "client_ip" => "1.2.3.4",
        "qname" => "x.test",
        "qtype" => :a,
        "decision" => :allow
      })

    {:ok, %{"truncated" => true}} = Plugin.handle_action("clear_query_log", %{})
    assert %{rows: []} = Storage.read_query_log(%{})
  end

  test "unknown action → :unknown_action error" do
    assert {:error, {:unknown_action, "nope"}} = Plugin.handle_action("nope", %{})
  end
end
