defmodule ExDns.Resolver.WorkerTelemetryTest do
  @moduledoc """
  Verifies that the UDP resolver worker emits the documented
  `[:ex_dns, :query, :start]` and `[:ex_dns, :query, :stop]`
  telemetry events, with the metadata shape declared in
  `ExDns.Telemetry`.
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}

  @test_port 8051

  setup do
    # Other tests (integration tests in particular) stop the
    # application in their `on_exit` and reset the listener port.
    # Pin the port to a value of our own and restart so we know
    # exactly where to send the query.
    Application.stop(:ex_dns)
    Application.put_env(:ex_dns, :listener_port, @test_port)
    {:ok, _} = Application.ensure_all_started(:ex_dns)

    on_exit(fn -> :telemetry.detach("worker-telemetry-test") end)
    :ok
  end

  defp build_query(qname, qtype) do
    %Message{
      header: %Header{
        id: 0xBEEF,
        qr: 0,
        oc: 0,
        aa: 0,
        tc: 0,
        rd: 1,
        ra: 0,
        ad: 0,
        cd: 0,
        rc: 0,
        qc: 1,
        anc: 0,
        auc: 0,
        adc: 0
      },
      question: %Question{host: qname, type: qtype, class: :in},
      answer: [],
      authority: [],
      additional: []
    }
    |> Message.encode_for_udp(512)
  end

  test "UDP worker emits :query.start and :query.stop with documented metadata" do
    test_pid = self()

    :telemetry.attach_many(
      "worker-telemetry-test",
      [
        [:ex_dns, :query, :start],
        [:ex_dns, :query, :stop]
      ],
      fn event, measurements, metadata, _config ->
        send(test_pid, {:event, event, measurements, metadata})
      end,
      %{}
    )

    # Open a local UDP socket as the "client" and send a query at the
    # listener that the application supervisor started on port 8053.
    {:ok, client} = :gen_udp.open(0, [:binary, active: false])
    bytes = build_query("example.test", :a)
    :ok = :gen_udp.send(client, {127, 0, 0, 1}, @test_port, bytes)
    # Drain the reply so the kernel's UDP buffer doesn't fill in CI.
    _ = :gen_udp.recv(client, 0, 2_000)
    :gen_udp.close(client)

    assert_receive {:event, [:ex_dns, :query, :start], start_measurements,
                    start_metadata},
                   2_000

    assert is_integer(start_measurements.system_time)
    assert start_metadata.transport == :udp
    assert start_metadata.qname == "example.test"
    assert start_metadata.qtype == :a
    assert match?({{127, 0, 0, 1}, _port}, start_metadata.client)

    assert_receive {:event, [:ex_dns, :query, :stop], stop_measurements,
                    stop_metadata},
                   2_000

    assert is_integer(stop_measurements.duration)
    assert stop_measurements.duration > 0
    assert stop_metadata.transport == :udp
    assert stop_metadata.qname == "example.test"
    assert stop_metadata.qtype == :a
    assert is_integer(stop_metadata.rcode)
    assert is_integer(stop_metadata.answer_count)
    assert stop_metadata.validation in [:secure, :insecure, :bogus, :indeterminate, :none]
    assert stop_metadata.cache in [:hit, :miss, :none]
  end
end
