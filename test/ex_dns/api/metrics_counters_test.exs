defmodule ExDns.API.MetricsCountersTest do
  @moduledoc """
  Tests that the metrics-counter aggregator subscribes to the
  right telemetry events, increments correctly, and produces
  the expected JSON shape.
  """

  use ExUnit.Case, async: false

  alias ExDns.API.MetricsCounters

  setup do
    MetricsCounters.init()
    MetricsCounters.clear()
    :ok
  end

  test "queries are bucketed by qtype" do
    :telemetry.execute([:ex_dns, :query, :start], %{count: 1}, %{qtype: :a})
    :telemetry.execute([:ex_dns, :query, :start], %{count: 1}, %{qtype: :a})
    :telemetry.execute([:ex_dns, :query, :start], %{count: 1}, %{qtype: :aaaa})

    snapshot = MetricsCounters.snapshot()
    assert snapshot["queries"]["a"] == 2
    assert snapshot["queries"]["aaaa"] == 1
  end

  test "rrl drops increment a single counter" do
    :telemetry.execute([:ex_dns, :rrl, :drop], %{count: 1}, %{})
    :telemetry.execute([:ex_dns, :rrl, :drop], %{count: 1}, %{})

    assert MetricsCounters.snapshot()["rrl_drops"] == 2
  end

  test "cache hits + misses are split into hit / miss buckets" do
    :telemetry.execute([:ex_dns, :cache, :hit], %{count: 1}, %{})
    :telemetry.execute([:ex_dns, :cache, :hit], %{count: 1}, %{})
    :telemetry.execute([:ex_dns, :cache, :miss], %{count: 1}, %{})

    snapshot = MetricsCounters.snapshot()
    assert snapshot["cache_hits"]["hit"] == 2
    assert snapshot["cache_hits"]["miss"] == 1
  end

  test "DNSSEC validation outcomes are bucketed by status" do
    :telemetry.execute(
      [:ex_dns, :dnssec, :validate, :stop],
      %{},
      %{status: :secure}
    )

    :telemetry.execute(
      [:ex_dns, :dnssec, :validate, :stop],
      %{},
      %{status: :bogus}
    )

    snapshot = MetricsCounters.snapshot()
    assert snapshot["dnssec"]["secure"] == 1
    assert snapshot["dnssec"]["bogus"] == 1
  end

  test "snapshot/1 echoes the requested window" do
    snapshot = MetricsCounters.snapshot(120)
    assert snapshot["window_seconds"] == 120
  end

  test "empty snapshot returns the documented shape" do
    snapshot = MetricsCounters.snapshot()
    assert snapshot["queries"] == %{}
    assert snapshot["rrl_drops"] == 0
    assert snapshot["cache_hits"] == %{"hit" => 0, "miss" => 0}
    assert snapshot["dnssec"] == %{}
  end
end
