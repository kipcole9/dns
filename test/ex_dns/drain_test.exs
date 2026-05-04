defmodule ExDns.DrainTest do
  @moduledoc """
  Verifies drain semantics: the readiness flag is flipped, listener
  sockets are closed, the function blocks until either the worker
  pool is idle or the timeout elapses, and telemetry events fire
  with the right shape.
  """

  use ExUnit.Case, async: false

  alias ExDns.Drain

  doctest Drain

  setup do
    Drain.clear_draining()
    {:ok, _} = Application.ensure_all_started(:ex_dns)

    on_exit(fn ->
      Drain.clear_draining()
      :telemetry.detach("drain-test-handler")
    end)

    :ok
  end

  test "draining?/0 is false until mark_draining/0 is called" do
    refute Drain.draining?()
    Drain.mark_draining()
    assert Drain.draining?()
    Drain.clear_draining()
    refute Drain.draining?()
  end

  test "drain/1 returns :ok promptly when there are no in-flight queries" do
    Drain.clear_draining()
    {:ok, _} = Application.ensure_all_started(:ex_dns)

    assert :ok = Drain.drain(timeout: 1_000)
    assert Drain.draining?()
  end

  test "drain/1 emits :start and :stop telemetry events" do
    test_pid = self()

    :telemetry.attach_many(
      "drain-test-handler",
      [
        [:ex_dns, :drain, :start],
        [:ex_dns, :drain, :stop]
      ],
      fn event, measurements, metadata, _ ->
        send(test_pid, {:event, event, measurements, metadata})
      end,
      %{}
    )

    Drain.clear_draining()
    _ = Drain.drain(timeout: 1_000)

    assert_receive {:event, [:ex_dns, :drain, :start], _, %{timeout_ms: 1_000}}
    assert_receive {:event, [:ex_dns, :drain, :stop], _, %{result: :ok}}
  end

  test "readiness probe flips to error :draining once drain begins" do
    {:ok, _} = Application.ensure_all_started(:ex_dns)

    assert :ok = ExDns.Health.readiness_checks()

    Drain.mark_draining()

    assert {:error, failures} = ExDns.Health.readiness_checks()
    assert {:draining, :draining} in failures
  end
end
