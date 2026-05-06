defmodule ExDns.RRLTest do
  @moduledoc """
  Verifies the RRL token-bucket logic: bursts are allowed,
  sustained over-rate produces drops, the slip mechanism converts
  every Nth drop into a TC=1 truncation, cookie-validated requests
  bypass the limiter entirely, and disabling the feature falls
  open.
  """

  use ExUnit.Case, async: false

  alias ExDns.RRL

  doctest RRL

  setup do
    previous = Application.get_env(:ex_dns, :rrl)
    RRL.clear()

    on_exit(fn ->
      RRL.clear()

      case previous do
        nil -> Application.delete_env(:ex_dns, :rrl)
        other -> Application.put_env(:ex_dns, :rrl, other)
      end
    end)

    :ok
  end

  defp configure(opts) do
    Application.put_env(:ex_dns, :rrl, [enabled: true] ++ opts)
  end

  test "feature flag off → always :allow" do
    # RRL defaults to enabled (T1.6) — operators opting out
    # set `enabled: false` explicitly. Make that explicit here.
    Application.put_env(:ex_dns, :rrl, enabled: false)

    Enum.each(1..100, fn _ ->
      assert :allow = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
    end)
  end

  test "burst is allowed, then queries beyond burst are dropped" do
    configure(responses_per_second: 1, burst: 3, slip: 1_000_000)

    assert :allow = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
    assert :allow = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
    assert :allow = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)

    # 4th in the same instant → bucket empty → :drop (slip set very
    # high so it never converts to :slip in this test).
    assert :drop = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
  end

  test "every Nth drop is converted to :slip" do
    configure(responses_per_second: 0.0001, burst: 1, slip: 2)

    # Burn the budget.
    assert :allow = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
    # First post-burst → drop, second → slip, third → drop, fourth → slip.
    assert :drop = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
    assert :slip = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
    assert :drop = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
    assert :slip = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
  end

  test "cookie-validated queries bypass RRL" do
    configure(responses_per_second: 0.0001, burst: 1, slip: 1_000_000)

    assert :allow = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
    # No cookie → :drop.
    assert :drop = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
    # With cookie → :allow regardless of bucket state.
    assert :allow = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer, cookie_validated: true)
    assert :allow = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer, cookie_validated: true)
  end

  test "different qnames use different buckets" do
    configure(responses_per_second: 0.0001, burst: 1)

    assert :allow = RRL.check({1, 2, 3, 4}, "first.test", :a, :answer)
    assert :allow = RRL.check({1, 2, 3, 4}, "second.test", :a, :answer)
    # Each is its own bucket, both got their one allow.
  end

  test "different response kinds use different buckets" do
    configure(responses_per_second: 0.0001, burst: 1)

    assert :allow = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
    assert :allow = RRL.check({1, 2, 3, 4}, "x.test", :a, :nxdomain)
  end

  test "/24 grouping: two clients in the same /24 share a bucket" do
    configure(responses_per_second: 0.0001, burst: 1, ipv4_prefix: 24, slip: 1_000_000)

    assert :allow = RRL.check({10, 0, 0, 1}, "x.test", :a, :answer)
    # Different IP, same /24 → same bucket → :drop.
    assert :drop = RRL.check({10, 0, 0, 99}, "x.test", :a, :answer)
  end

  test "/32 grouping: every IP gets its own bucket" do
    configure(responses_per_second: 0.0001, burst: 1, ipv4_prefix: 32)

    assert :allow = RRL.check({10, 0, 0, 1}, "x.test", :a, :answer)
    assert :allow = RRL.check({10, 0, 0, 2}, "x.test", :a, :answer)
  end

  test "tokens refill over time" do
    configure(responses_per_second: 1000, burst: 1, slip: 1_000_000)

    assert :allow = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
    # Wait long enough for the bucket to refill.
    Process.sleep(50)
    assert :allow = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
  end

  test "decision telemetry events fire" do
    configure(responses_per_second: 0.0001, burst: 1, slip: 1_000_000)

    test_pid = self()

    :telemetry.attach(
      "rrl-test",
      [:ex_dns, :rrl, :decision],
      fn _, _, metadata, _ -> send(test_pid, {:rrl, metadata}) end,
      %{}
    )

    on_exit(fn -> :telemetry.detach("rrl-test") end)

    assert :allow = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
    assert_receive {:rrl, %{decision: :allow, response_kind: :answer}}

    assert :drop = RRL.check({1, 2, 3, 4}, "x.test", :a, :answer)
    assert_receive {:rrl, %{decision: :drop, response_kind: :answer}}
  end
end
