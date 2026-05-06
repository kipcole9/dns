defmodule ExDns.DNSSEC.SigningLagTest do
  use ExUnit.Case, async: false

  alias ExDns.DNSSEC.SigningLag

  setup do
    SigningLag.init()
    SigningLag.reset()
    on_exit(&SigningLag.reset/0)
    :ok
  end

  describe "observe/2 + last_signed_at/1" do
    test "round-trips an inception timestamp" do
      assert :ok = SigningLag.observe("example.com", 1_700_000_000)
      assert 1_700_000_000 == SigningLag.last_signed_at("example.com")
    end

    test "is case- and trailing-dot-insensitive" do
      SigningLag.observe("Example.COM.", 42)
      assert 42 == SigningLag.last_signed_at("example.com")
    end

    test "second observation overwrites the first" do
      SigningLag.observe("a.test", 100)
      SigningLag.observe("a.test", 200)
      assert 200 == SigningLag.last_signed_at("a.test")
    end
  end

  describe "seconds_since_last_sign/2" do
    test "returns nil when nothing has been observed" do
      assert is_nil(SigningLag.seconds_since_last_sign("never.test"))
    end

    test "returns the elapsed seconds against an injectable :now" do
      SigningLag.observe("z.test", 100)
      assert 50 == SigningLag.seconds_since_last_sign("z.test", now: 150)
    end

    test "never returns a negative lag (clock skew defence)" do
      SigningLag.observe("z.test", 200)
      assert 0 == SigningLag.seconds_since_last_sign("z.test", now: 100)
    end
  end

  describe "all_lags/1" do
    test "returns one entry per observed zone" do
      SigningLag.observe("a.test", 100)
      SigningLag.observe("b.test", 200)

      lags = SigningLag.all_lags(now: 250) |> Enum.sort()
      assert lags == [{"a.test", 150}, {"b.test", 50}]
    end
  end

  describe "telemetry" do
    test "emits [:ex_dns, :dnssec, :signed]" do
      :telemetry.attach(
        "signing-lag-test",
        [:ex_dns, :dnssec, :signed],
        fn _, m, meta, _ -> send(self(), {:signed, m, meta}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach("signing-lag-test") end)

      SigningLag.observe("e.test", 12345)

      assert_received {:signed, %{inception: 12345}, %{zone: "e.test"}}
    end
  end
end
