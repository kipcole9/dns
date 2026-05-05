defmodule ExDns.Zone.Catalog.SubscriptionTest do
  @moduledoc """
  Verifies the catalog-zone polling state machine: detects
  serial changes, AXFRs on change, no-ops on stable serial,
  and tolerates upstream failures.

  A stub `Client` returns canned `fetch_soa/3` + `fetch_axfr/3`
  responses driven by an `Agent`, so the test never touches the
  network.
  """

  use ExUnit.Case, async: false

  alias ExDns.Resource.{PTR, SOA}
  alias ExDns.Storage
  alias ExDns.Zone.Catalog.Subscription

  defmodule StubClient do
    @moduledoc false
    @agent_name :catalog_stub_agent

    def setup_state(soa_results, axfr_results) do
      stop()

      {:ok, _} =
        Agent.start_link(
          fn ->
            %{soa: soa_results, axfr: axfr_results, soa_calls: 0, axfr_calls: 0}
          end,
          name: @agent_name
        )

      :ok
    end

    def stop do
      case Process.whereis(@agent_name) do
        nil -> :ok
        pid -> Agent.stop(pid)
      end
    end

    def call_counts do
      Agent.get(@agent_name, fn s -> {s.soa_calls, s.axfr_calls} end)
    end

    def fetch_soa(_apex, _primary, _options) do
      Agent.get_and_update(@agent_name, fn state ->
        result = next(state.soa, state.soa_calls)
        {result, %{state | soa_calls: state.soa_calls + 1}}
      end)
    end

    def fetch_axfr(_apex, _primary, _options) do
      Agent.get_and_update(@agent_name, fn state ->
        result = next(state.axfr, state.axfr_calls)
        {result, %{state | axfr_calls: state.axfr_calls + 1}}
      end)
    end

    defp next(list, idx) when is_list(list) do
      Enum.at(list, idx, List.last(list))
    end
  end

  setup do
    Storage.init()

    on_exit(fn ->
      Storage.delete_zone("first.test")
      Storage.delete_zone("second.test")
      StubClient.stop()
    end)

    :ok
  end

  defp soa(serial) do
    %SOA{
      name: "catalog.test",
      ttl: 60,
      class: :in,
      mname: "ns",
      email: "h",
      serial: serial,
      refresh: 60,
      retry: 60,
      expire: 60,
      minimum: 60
    }
  end

  defp catalog_records(member_names, serial) do
    [
      soa(serial)
      | Enum.with_index(member_names, fn name, idx ->
          %PTR{
            name: "id#{idx}.zones.catalog.test",
            ttl: 60,
            class: :in,
            pointer: name
          }
        end)
    ]
  end

  defp start_subscription(options \\ []) do
    base = [
      catalog_apex: "catalog.test",
      primaries: [{{127, 0, 0, 1}, 53}],
      poll_interval_seconds: 60,
      member_defaults: [primaries: [{{127, 0, 0, 1}, 53}]],
      client_module: StubClient
    ]

    {:ok, pid} = Subscription.start_link(Keyword.merge(base, options))

    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
    end)

    pid
  end

  test "first poll detects a fresh serial and applies the catalog" do
    StubClient.setup_state([{:ok, soa(7)}], [{:ok, catalog_records(["first.test"], 7)}])

    test_pid = self()

    :telemetry.attach(
      "cat-sub-test-#{System.unique_integer([:positive])}",
      [:ex_dns, :catalog, :poll, :stop],
      fn _, m, metadata, _ -> send(test_pid, {:poll_stop, m, metadata}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach("cat-sub-test") end)

    start_subscription()

    assert_receive {:poll_stop, %{members: 1}, %{decision: :applied}}, 500

    snap = Subscription.snapshot("catalog.test")
    assert snap.last_serial == 7
  end

  test "stable serial → :up_to_date, no AXFR call after the first" do
    StubClient.setup_state(
      [{:ok, soa(11)}, {:ok, soa(11)}, {:ok, soa(11)}],
      [{:ok, catalog_records(["first.test"], 11)}]
    )

    test_pid = self()

    :telemetry.attach(
      "cat-sub-stable-#{System.unique_integer([:positive])}",
      [:ex_dns, :catalog, :poll, :stop],
      fn _, _, metadata, _ -> send(test_pid, {:poll, metadata}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach("cat-sub-stable") end)

    start_subscription()
    assert_receive {:poll, %{decision: :applied}}, 500

    Subscription.poll_now("catalog.test")
    assert_receive {:poll, %{decision: :up_to_date}}, 500

    {soa_calls, axfr_calls} = StubClient.call_counts()
    assert soa_calls >= 2
    # Only one AXFR — the initial apply.
    assert axfr_calls == 1
  end

  test "serial change triggers a fresh AXFR + Applier reconciliation" do
    StubClient.setup_state(
      [{:ok, soa(1)}, {:ok, soa(2)}],
      [
        {:ok, catalog_records(["first.test"], 1)},
        {:ok, catalog_records(["first.test", "second.test"], 2)}
      ]
    )

    test_pid = self()

    :telemetry.attach(
      "cat-sub-change-#{System.unique_integer([:positive])}",
      [:ex_dns, :catalog, :poll, :stop],
      fn _, m, metadata, _ -> send(test_pid, {:poll, m, metadata}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach("cat-sub-change") end)

    start_subscription()

    assert_receive {:poll, %{members: 1}, %{decision: :applied}}, 500

    Subscription.poll_now("catalog.test")
    assert_receive {:poll, %{members: 2}, %{decision: :applied}}, 500

    snap = Subscription.snapshot("catalog.test")
    assert snap.last_serial == 2
  end

  test "SOA failure surfaces as :soa_failed and preserves last_serial" do
    StubClient.setup_state([{:error, :timeout}], [])

    test_pid = self()

    :telemetry.attach(
      "cat-sub-soa-fail-#{System.unique_integer([:positive])}",
      [:ex_dns, :catalog, :poll, :stop],
      fn _, _, metadata, _ -> send(test_pid, {:poll, metadata}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach("cat-sub-soa-fail") end)

    start_subscription()

    assert_receive {:poll, %{decision: :soa_failed}}, 500

    snap = Subscription.snapshot("catalog.test")
    assert is_nil(snap.last_serial)
  end

  test "AXFR failure surfaces as :axfr_failed; serial NOT advanced" do
    StubClient.setup_state([{:ok, soa(99)}], [{:error, :timeout}])

    test_pid = self()

    :telemetry.attach(
      "cat-sub-axfr-fail-#{System.unique_integer([:positive])}",
      [:ex_dns, :catalog, :poll, :stop],
      fn _, _, metadata, _ -> send(test_pid, {:poll, metadata}) end,
      nil
    )

    on_exit(fn -> :telemetry.detach("cat-sub-axfr-fail") end)

    start_subscription()

    assert_receive {:poll, %{decision: :axfr_failed}}, 500

    snap = Subscription.snapshot("catalog.test")
    assert is_nil(snap.last_serial)
  end

  test "snapshot/1 returns nil when no subscription is registered" do
    assert is_nil(Subscription.snapshot("nothing.test"))
  end
end
