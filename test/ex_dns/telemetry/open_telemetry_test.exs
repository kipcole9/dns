defmodule ExDns.Telemetry.OpenTelemetryTest do
  @moduledoc """
  Verifies the OpenTelemetry bridge attaches to query events and
  the handlers run cleanly. The `:opentelemetry_api` package is
  loaded in the test environment but no SDK is configured, so
  span operations are no-ops — exactly the production setup an
  operator gets when they enable tracing without an exporter.
  Confirms we don't crash either way.
  """

  use ExUnit.Case, async: false

  alias ExDns.Telemetry.OpenTelemetry

  doctest OpenTelemetry

  setup do
    on_exit(fn -> OpenTelemetry.detach() end)
    :ok
  end

  test "attach/0 succeeds when :opentelemetry_api is loaded" do
    assert :ok = OpenTelemetry.attach()
  end

  test "handle_event/4 runs cleanly for :start and :stop with the no-op tracer" do
    :ok = OpenTelemetry.attach()

    metadata = %{
      transport: :udp,
      qname: "example.test",
      qtype: :a,
      client: {{127, 0, 0, 1}, 53_000}
    }

    assert :ok = :telemetry.execute([:ex_dns, :query, :start], %{system_time: 1}, metadata)

    stop_metadata =
      Map.merge(metadata, %{rcode: 0, answer_count: 1, cache: :miss, validation: :none})

    assert :ok =
             :telemetry.execute([:ex_dns, :query, :stop], %{duration: 1_000_000}, stop_metadata)
  end

  test "handle_event/4 runs cleanly for :exception" do
    :ok = OpenTelemetry.attach()

    :ok = :telemetry.execute([:ex_dns, :query, :start], %{system_time: 1}, %{transport: :udp})

    assert :ok =
             :telemetry.execute(
               [:ex_dns, :query, :exception],
               %{duration: 100},
               %{kind: :error, reason: :boom, stacktrace: []}
             )
  end

  test "handle_event/4 with no open span (orphan :stop) is a safe no-op" do
    :ok = OpenTelemetry.attach()

    # Note: no :start before this :stop.
    assert :ok =
             :telemetry.execute(
               [:ex_dns, :query, :stop],
               %{duration: 100},
               %{rcode: 0, answer_count: 1}
             )
  end
end
