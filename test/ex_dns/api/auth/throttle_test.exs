defmodule ExDns.API.Auth.ThrottleTest do
  @moduledoc """
  Verifies the per-IP authentication-failure throttle.
  """

  use ExUnit.Case, async: false

  alias ExDns.API.Auth.Throttle

  setup do
    previous = Application.get_env(:ex_dns, :api_auth_throttle)

    Application.put_env(:ex_dns, :api_auth_throttle,
      enabled: true,
      burst: 3,
      refill_seconds: 60,
      cooldown_seconds: 120
    )

    Throttle.reset()

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :api_auth_throttle)
        v -> Application.put_env(:ex_dns, :api_auth_throttle, v)
      end

      Throttle.reset()
    end)

    :ok
  end

  describe "check/1" do
    test "returns :ok for an IP with no recorded failures" do
      assert :ok = Throttle.check({127, 0, 0, 1})
    end

    test "returns :ok up to the burst, then throttles" do
      ip = {10, 0, 0, 1}

      Enum.each(1..3, fn _ ->
        assert :ok = Throttle.check(ip)
        Throttle.record_failure(ip)
      end)

      # Bucket exhausted; next attempt is throttled.
      assert {:error, :throttled, retry_after} = Throttle.check(ip)
      assert retry_after > 0
    end

    test "returns :ok when ip is nil (e.g. unit-tests with no remote_ip)" do
      assert :ok = Throttle.check(nil)
    end
  end

  describe "record_success/1" do
    test "wipes throttle state for the IP" do
      ip = {10, 0, 0, 2}

      Enum.each(1..3, fn _ -> Throttle.record_failure(ip) end)
      assert {:error, :throttled, _} = Throttle.check(ip)

      Throttle.record_success(ip)
      assert :ok = Throttle.check(ip)
    end
  end

  describe "enabled: false" do
    test "every IP is permitted regardless of failure count" do
      Application.put_env(:ex_dns, :api_auth_throttle, enabled: false)

      ip = {10, 0, 0, 3}
      Enum.each(1..50, fn _ -> Throttle.record_failure(ip) end)

      assert :ok = Throttle.check(ip)
    end
  end
end
