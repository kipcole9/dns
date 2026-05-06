defmodule ExDns.PauseModeTest do
  use ExUnit.Case, async: false

  alias ExDns.PauseMode

  setup do
    PauseMode.unpause()
    on_exit(&PauseMode.unpause/0)
    :ok
  end

  describe "pause/1 + paused?/0" do
    test "starts unpaused" do
      refute PauseMode.paused?()
    end

    test "indefinite pause stays on until unpause/0" do
      PauseMode.pause(:until_unpaused)
      assert PauseMode.paused?()
      assert PauseMode.paused?()

      PauseMode.unpause()
      refute PauseMode.paused?()
    end

    test "bounded pause auto-clears after the deadline" do
      # Use 1-second pause and wait it out — fastest test
      # that exercises the auto-clear path.
      PauseMode.pause(1)
      assert PauseMode.paused?()

      :timer.sleep(1100)

      # First post-deadline check returns false AND clears
      # the state.
      refute PauseMode.paused?()

      # Status reflects the cleared state.
      assert PauseMode.status() == %{paused: false}
    end
  end

  describe "status/0" do
    test "%{paused: false} when not paused" do
      assert PauseMode.status() == %{paused: false}
    end

    test "indefinite pause has expires_at: nil" do
      PauseMode.pause(:until_unpaused)
      assert %{paused: true, expires_at: nil, remaining_seconds: nil} = PauseMode.status()
    end

    test "bounded pause exposes remaining_seconds" do
      PauseMode.pause(60)
      status = PauseMode.status()
      assert status.paused == true
      assert status.remaining_seconds in 58..60
      assert is_integer(status.expires_at)
    end
  end
end
