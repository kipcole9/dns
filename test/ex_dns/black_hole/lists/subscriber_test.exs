defmodule ExDns.BlackHole.Lists.SubscriberTest do
  @moduledoc """
  Tests the blocklist subscriber: 200 → parse + on_refresh,
  304 → no parse, error → status recorded. The fetcher is
  driven via `Req`'s `:plug` adapter so the test never opens
  a socket.
  """

  use ExUnit.Case, async: false

  alias ExDns.BlackHole.Lists.Subscriber

  setup do
    test_pid = self()

    on_refresh = fn payload -> send(test_pid, {:on_refresh, payload}) end

    {:ok, on_refresh: on_refresh, test_pid: test_pid}
  end

  defp start_with(id, plug, on_refresh) do
    {:ok, pid} =
      Subscriber.start_link(
        id: id,
        url: "http://stub.local/list.txt",
        on_refresh: on_refresh,
        initial_delay_ms: 0,
        interval_ms: 60_000,
        req_options: [plug: plug]
      )

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
    end)

    pid
  end

  defp plug_returning(status, body, headers \\ []) do
    fn conn ->
      conn = Enum.reduce(headers, conn, fn {k, v}, c -> Plug.Conn.put_resp_header(c, k, v) end)
      Plug.Conn.send_resp(conn, status, body)
    end
  end

  test "200 → parses + invokes on_refresh", %{on_refresh: on_refresh} do
    body = "0.0.0.0 ads.example\n||tracker.example^\n"
    plug = plug_returning(200, body, [{"etag", "v1"}])

    start_with("list-1", plug, on_refresh)

    assert_receive {:on_refresh, {"list-1", ["ads.example", "tracker.example"]}}, 500
  end

  test "304 → does not call on_refresh", %{on_refresh: on_refresh} do
    plug = plug_returning(304, "", [{"etag", "v2"}])

    start_with("list-2", plug, on_refresh)

    refute_receive {:on_refresh, _}, 200
  end

  test "error → status recorded, no on_refresh", %{on_refresh: on_refresh} do
    plug = plug_returning(503, "down")
    start_with("list-3", plug, on_refresh)

    refute_receive {:on_refresh, _}, 200

    snap = Subscriber.snapshot("list-3")
    assert snap.last_status =~ "503"
  end

  test "telemetry fires on each cycle", %{on_refresh: on_refresh} do
    plug = plug_returning(200, "x.example\ny.example\n")
    test_pid = self()

    :telemetry.attach(
      "subscriber-test-#{System.unique_integer([:positive])}",
      [:ex_dns, :black_hole, :list, :refreshed],
      fn _, m, metadata, _ -> send(test_pid, {:event, m, metadata}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach("subscriber-test") end)

    start_with("list-4", plug, on_refresh)

    assert_receive {:event, %{entries: 2}, %{list_id: "list-4", status: "200"}}, 500
  end
end
