defmodule ExDns.TelemetryTest do
  @moduledoc """
  Exercises the `ExDns.Telemetry` events catalogue: doctests, the
  contents of `events/0`, and that `attach_default_logger/1` actually
  attaches a working :telemetry handler.
  """

  use ExUnit.Case, async: false

  doctest ExDns.Telemetry

  setup do
    on_exit(fn ->
      :telemetry.detach("ex-dns-default-log")
      :telemetry.detach("ex-dns-test-handler")
    end)

    :ok
  end

  test "events/0 lists the canonical lifecycle events" do
    events = ExDns.Telemetry.events()

    assert [:ex_dns, :query, :start] in events
    assert [:ex_dns, :query, :stop] in events
    assert [:ex_dns, :dnssec, :validate, :stop] in events
    assert [:ex_dns, :tsig, :verify, :stop] in events
    assert [:ex_dns, :axfr, :transfer, :stop] in events
    assert [:ex_dns, :cache, :hit] in events
    assert [:ex_dns, :cache, :miss] in events

    # All event names are lists of atoms, namespaced under :ex_dns.
    Enum.each(events, fn event ->
      assert is_list(event)
      assert hd(event) == :ex_dns
      Enum.each(event, &assert(is_atom(&1)))
    end)
  end

  test "attach_default_logger/1 attaches every catalogue event" do
    :ok = ExDns.Telemetry.attach_default_logger("ex-dns-default-log")

    attached =
      :telemetry.list_handlers([:ex_dns, :query, :stop])
      |> Enum.map(& &1.id)

    assert "ex-dns-default-log" in attached
  end

  test "emitted events reach a handler attached via the catalogue" do
    test_pid = self()

    :telemetry.attach_many(
      "ex-dns-test-handler",
      ExDns.Telemetry.events(),
      fn event, measurements, metadata, _config ->
        send(test_pid, {:event, event, measurements, metadata})
      end,
      %{}
    )

    :telemetry.execute(
      [:ex_dns, :cache, :hit],
      %{count: 1},
      %{layer: :recursor, qname: "example.test", qtype: :a}
    )

    assert_receive {:event, [:ex_dns, :cache, :hit], %{count: 1},
                    %{layer: :recursor, qname: "example.test", qtype: :a}}
  end
end
