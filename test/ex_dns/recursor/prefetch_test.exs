defmodule ExDns.Recursor.PrefetchTest do
  @moduledoc """
  Verifies the prefetch coordinator: dedup behaviour, the
  prefetch-window gate, and the disabled-by-config short-circuit.
  Refresher functions write a marker to a shared `Agent` so the
  test can observe whether the prefetch task ran.
  """

  use ExUnit.Case, async: false

  alias ExDns.Recursor.{Cache, Prefetch}
  alias ExDns.Resource.A

  setup do
    Cache.init()
    Cache.clear()
    Prefetch.init()
    Prefetch.clear()

    previous_enabled = Application.get_env(:ex_dns, :recursor_prefetch_enabled)

    on_exit(fn ->
      Cache.clear()
      Prefetch.clear()

      case previous_enabled do
        nil -> Application.delete_env(:ex_dns, :recursor_prefetch_enabled)
        v -> Application.put_env(:ex_dns, :recursor_prefetch_enabled, v)
      end
    end)

    {:ok, agent} = Agent.start_link(fn -> [] end)
    {:ok, agent: agent}
  end

  defp record_call(agent, name, type, value \\ :called) do
    fn ->
      Agent.update(agent, &[{name, type, value} | &1])
      :ok
    end
  end

  defp put_in_window(name, type, ttl \\ 100) do
    record = %A{name: name, ttl: ttl, class: :in, ipv4: {1, 2, 3, 4}}
    Cache.put(name, type, [record], ttl)

    [{key, kind, payload, _, original_ttl}] =
      :ets.lookup(:ex_dns_recursor_cache, {name, type})

    :ets.insert(
      :ex_dns_recursor_cache,
      {key, kind, payload, :erlang.monotonic_time(:second) + 5, original_ttl}
    )
  end

  describe "maybe_prefetch/4" do
    test "schedules a prefetch when in window and not in flight",
         %{agent: agent} do
      put_in_window("hot.test", :a)

      assert :scheduled =
               Prefetch.maybe_prefetch("hot.test", :a, record_call(agent, "hot.test", :a))

      # Wait for the spawned task to finish.
      Process.sleep(20)
      assert [{"hot.test", :a, :called}] = Agent.get(agent, & &1)
    end

    test "skips a duplicate prefetch while one is in flight" do
      put_in_window("dup.test", :a)
      test_pid = self()

      slow_refresher = fn ->
        send(test_pid, :first_started)
        # Block long enough for a second call to race.
        Process.sleep(80)
        :ok
      end

      assert :scheduled = Prefetch.maybe_prefetch("dup.test", :a, slow_refresher)
      assert_receive :first_started, 200

      assert :already_in_flight =
               Prefetch.maybe_prefetch("dup.test", :a, fn ->
                 send(test_pid, :second_ran)
                 :ok
               end)

      refute_received :second_ran

      # Allow the first to finish, then a third call may schedule.
      Process.sleep(120)

      assert :scheduled =
               Prefetch.maybe_prefetch("dup.test", :a, fn ->
                 send(test_pid, :third_ran)
                 :ok
               end)

      assert_receive :third_ran, 200
    end

    test ":not_in_window when nothing is cached" do
      assert :not_in_window =
               Prefetch.maybe_prefetch("nothing.test", :a, fn -> :ok end)
    end

    test ":not_in_window for a still-fresh entry" do
      record = %A{name: "young.test", ttl: 600, class: :in, ipv4: {1, 2, 3, 4}}
      Cache.put("young.test", :a, [record], 600)

      assert :not_in_window =
               Prefetch.maybe_prefetch("young.test", :a, fn -> :ok end)
    end

    test "respects :recursor_prefetch_enabled = false" do
      Application.put_env(:ex_dns, :recursor_prefetch_enabled, false)
      put_in_window("disabled.test", :a)

      test_pid = self()

      assert :not_in_window =
               Prefetch.maybe_prefetch("disabled.test", :a, fn ->
                 send(test_pid, :ran)
                 :ok
               end)

      refute_received :ran
    end

    test "telemetry :start + :stop fire on a scheduled prefetch" do
      put_in_window("telem.test", :a)
      test_pid = self()

      handler = fn event, _measurements, metadata, _ ->
        send(test_pid, {event, metadata})
      end

      :telemetry.attach_many(
        "prefetch-test",
        [
          [:ex_dns, :recursor, :prefetch, :start],
          [:ex_dns, :recursor, :prefetch, :stop]
        ],
        handler,
        nil
      )

      on_exit(fn -> :telemetry.detach("prefetch-test") end)

      assert :scheduled = Prefetch.maybe_prefetch("telem.test", :a, fn -> :ok end)

      assert_receive {[:ex_dns, :recursor, :prefetch, :start],
                      %{qname: "telem.test", qtype: :a}}

      assert_receive {[:ex_dns, :recursor, :prefetch, :stop],
                      %{qname: "telem.test", qtype: :a, result: :ok}},
                     500
    end

    test "telemetry :skipped fires when a prefetch is gated out" do
      test_pid = self()

      handler = fn event, _measurements, metadata, _ ->
        send(test_pid, {event, metadata})
      end

      :telemetry.attach(
        "prefetch-skip-test",
        [:ex_dns, :recursor, :prefetch, :skipped],
        handler,
        nil
      )

      on_exit(fn -> :telemetry.detach("prefetch-skip-test") end)

      Prefetch.maybe_prefetch("missing.test", :a, fn -> :ok end)

      assert_receive {[:ex_dns, :recursor, :prefetch, :skipped],
                      %{qname: "missing.test", qtype: :a, reason: :not_in_window}}
    end
  end
end
