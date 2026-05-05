defmodule ExDns.API.EventsTest do
  @moduledoc """
  Verifies the SSE event broker — subscription, broadcast,
  monitor-cleanup on subscriber death, telemetry-attach plumbing,
  and the SSE wire frame renderer.
  """

  use ExUnit.Case, async: false

  alias ExDns.API.Events

  setup do
    case Process.whereis(Events) do
      nil ->
        {:ok, _} = Events.start_link()

      _ ->
        :ok
    end

    on_exit(fn -> :telemetry.detach("ex_dns_api_events") end)
    :ok
  end

  describe "subscribe/0 + broadcast/2" do
    test "a subscribed pid receives broadcast events" do
      Events.subscribe()
      Events.broadcast(:hello, %{"foo" => 1})

      assert_receive {:exdns_event, :hello, %{"foo" => 1}}, 200
    end

    test "subscribers/0 reflects current count" do
      before_count = Events.subscribers()
      Events.subscribe()
      assert Events.subscribers() == before_count + 1
    end

    test "subscriber death cleans up the registry" do
      pid =
        spawn(fn ->
          Events.subscribe(self())
          receive do: ({:die, _} -> :ok)
        end)

      Process.sleep(50)
      before_count = Events.subscribers()

      Process.exit(pid, :kill)
      Process.sleep(50)

      assert Events.subscribers() == before_count - 1
    end

    test "duplicate subscribe is idempotent" do
      Events.subscribe()
      count = Events.subscribers()
      Events.subscribe()
      assert Events.subscribers() == count
    end
  end

  describe "render_sse/2" do
    test "produces the standard SSE wire frame" do
      frame =
        Events.render_sse(:zone_reloaded, %{"apex" => "example.test"})
        |> IO.iodata_to_binary()

      assert frame =~ "event: zone_reloaded\n"
      assert frame =~ ~s|data: {"apex":"example.test"}|
      assert String.ends_with?(frame, "\n\n")
    end
  end

  describe "attach_telemetry/0" do
    test "fires :secondary.loaded on the wire" do
      assert :ok = Events.attach_telemetry()
      Events.subscribe()

      :telemetry.execute(
        [:ex_dns, :secondary, :loaded],
        %{count: 1},
        %{zone: "x.test", serial: 5, kind: :axfr}
      )

      assert_receive {:exdns_event, :"secondary.loaded", payload}, 200
      assert payload["zone"] == "x.test"
      assert payload["serial"] == 5
      # Atom values get stringified so the JSON encoder can
      # render them as plain strings rather than tagged atoms.
      assert payload["kind"] == "axfr"
    end

    test "fires :catalog.polled with the merged measurement+metadata" do
      assert :ok = Events.attach_telemetry()
      Events.subscribe()

      :telemetry.execute(
        [:ex_dns, :catalog, :poll, :stop],
        %{members: 3, duration: 99},
        %{catalog_apex: "catalog.test", decision: :applied, serial_changed?: true}
      )

      assert_receive {:exdns_event, :"catalog.polled", payload}, 200
      assert payload["members"] == 3
      assert payload["catalog_apex"] == "catalog.test"
      assert payload["decision"] == "applied"
    end
  end
end
