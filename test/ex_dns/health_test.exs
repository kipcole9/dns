defmodule ExDns.HealthTest do
  @moduledoc """
  Verifies the /healthz and /readyz probes do what orchestrators
  expect: liveness is unconditional, readiness aggregates per-
  subsystem checks and returns 503 + a body identifying the failed
  check.
  """

  use ExUnit.Case, async: false

  use Plug.Test

  doctest ExDns.Health

  test "/healthz returns 200 ok" do
    conn =
      :get
      |> conn("/healthz", "")
      |> ExDns.Health.call([])

    assert conn.status == 200
    assert conn.resp_body =~ "ok"
  end

  test "/readyz returns 200 when every subsystem is up" do
    {:ok, _} = Application.ensure_all_started(:ex_dns)

    conn =
      :get
      |> conn("/readyz", "")
      |> ExDns.Health.call([])

    assert conn.status == 200
    assert conn.resp_body =~ "ready"
  end

  test "unknown route returns 404" do
    conn =
      :get
      |> conn("/missing", "")
      |> ExDns.Health.call([])

    assert conn.status == 404
  end

  test "readiness_checks/0 returns :ok when subsystems are running" do
    {:ok, _} = Application.ensure_all_started(:ex_dns)
    assert :ok = ExDns.Health.readiness_checks()
  end
end
