defmodule ExDns.Telemetry.StructuredLoggerTest do
  @moduledoc """
  Verifies the structured-log telemetry handler emits one log line
  per event, in `key=value` form, with the documented field set.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ExDns.Telemetry.StructuredLogger

  doctest StructuredLogger

  setup do
    on_exit(fn -> StructuredLogger.detach("structured-logger-test") end)
    :ok
  end

  test "logs a query.stop event in logfmt-style key=value form" do
    :ok = StructuredLogger.attach("structured-logger-test")

    log =
      capture_log(fn ->
        :telemetry.execute(
          [:ex_dns, :query, :stop],
          %{duration: System.convert_time_unit(123, :microsecond, :native)},
          %{
            transport: :udp,
            qname: "example.test",
            qtype: :a,
            rcode: 0,
            answer_count: 1,
            cache: :miss,
            validation: :none,
            client: {{127, 0, 0, 1}, 53_000}
          }
        )

        # Give Logger a tick to flush.
        Logger.flush()
      end)

    assert log =~ "event=ex_dns.query.stop"
    assert log =~ "duration_us=123"
    assert log =~ "transport=udp"
    assert log =~ "qname=example.test"
    assert log =~ "qtype=a"
    assert log =~ "rcode=0"
    assert log =~ "answer_count=1"
    assert log =~ "cache=miss"
    assert log =~ "validation=none"
    assert log =~ "client=127.0.0.1:53000"
  end

  test "instantaneous events have no duration_us field" do
    :ok = StructuredLogger.attach("structured-logger-test")

    log =
      capture_log(fn ->
        :telemetry.execute(
          [:ex_dns, :cache, :hit],
          %{count: 1},
          %{layer: :recursor, qname: "x.test", qtype: :a}
        )

        Logger.flush()
      end)

    assert log =~ "event=ex_dns.cache.hit"
    assert log =~ "layer=recursor"
    refute log =~ "duration_us="
  end

  test "binary values containing spaces are quoted" do
    :ok = StructuredLogger.attach("structured-logger-test")

    log =
      capture_log(fn ->
        :telemetry.execute(
          [:ex_dns, :tsig, :verify, :stop],
          %{duration: 0},
          %{key_name: "shared key", result: :ok}
        )

        Logger.flush()
      end)

    assert log =~ ~s(key_name="shared key")
  end
end
