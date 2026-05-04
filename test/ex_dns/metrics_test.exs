defmodule ExDns.MetricsTest do
  @moduledoc """
  Verifies the Prometheus exporter end-to-end: start the exporter
  under our supervision tree, fire synthetic telemetry events, scrape
  the `/metrics` endpoint, and assert the documented metric series
  appear with non-zero values.
  """

  use ExUnit.Case, async: false

  doctest ExDns.Metrics

  @port 9999

  setup do
    {:ok, sup} =
      Supervisor.start_link(
        [ExDns.Metrics.child_spec(port: @port, name: :ex_dns_prometheus_test)],
        strategy: :one_for_one
      )

    on_exit(fn ->
      ref = Process.monitor(sup)
      Process.exit(sup, :shutdown)

      receive do
        {:DOWN, ^ref, :process, ^sup, _} -> :ok
      after
        2_000 -> :ok
      end
    end)

    :ok
  end

  defp scrape do
    {:ok, conn} = :gen_tcp.connect(~c"127.0.0.1", @port, [:binary, active: false], 1_000)

    request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    :ok = :gen_tcp.send(conn, request)

    body = read_all(conn, "")
    :gen_tcp.close(conn)
    body
  end

  defp read_all(conn, acc) do
    case :gen_tcp.recv(conn, 0, 1_000) do
      {:ok, data} -> read_all(conn, acc <> data)
      {:error, :closed} -> acc
      {:error, _} -> acc
    end
  end

  test "metrics/0 declares the canonical DNS metric set" do
    names = ExDns.Metrics.metrics() |> Enum.map(& &1.name)

    assert [:dns, :queries, :total] in names
    assert [:dns, :query, :duration, :microseconds] in names
    assert [:dns, :cache, :hits, :total] in names
    assert [:dns, :cache, :misses, :total] in names
    assert [:dns, :dnssec, :validations, :total] in names
    assert [:dns, :tsig, :verifications, :total] in names
    assert [:dns, :axfr, :transfers, :total] in names
  end

  test "synthetic events surface in /metrics scrape output" do
    :telemetry.execute(
      [:ex_dns, :query, :stop],
      %{duration: System.convert_time_unit(120, :microsecond, :native)},
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

    :telemetry.execute(
      [:ex_dns, :cache, :hit],
      %{count: 1},
      %{layer: :recursor, qname: "x.test", qtype: :a}
    )

    :telemetry.execute(
      [:ex_dns, :dnssec, :validate, :stop],
      %{duration: 0},
      %{qname: "secure.test", qtype: :a, status: :secure}
    )

    body = scrape()

    assert body =~ "200 OK"
    assert body =~ "dns_queries_total"
    assert body =~ ~s(transport="udp")
    assert body =~ ~s(qtype="a")
    assert body =~ "dns_cache_hits_total"
    assert body =~ ~s(layer="recursor")
    assert body =~ "dns_dnssec_validations_total"
    assert body =~ ~s(status="secure")
    assert body =~ "dns_query_duration_microseconds"
  end
end
