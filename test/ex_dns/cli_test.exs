defmodule ExDns.CLITest do
  @moduledoc """
  Operator-CLI dispatch — exercised end-to-end via the same
  function the shell wrapper invokes. Coverage of every
  subcommand documented in `ExDns.CLI.dispatch/1`'s help.
  """

  use ExUnit.Case, async: false

  alias ExDns.{CLI, PauseMode}
  alias ExDns.API.TokenStore

  setup do
    PauseMode.unpause()

    token_path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_cli_tokens_#{System.unique_integer([:positive])}.json"
      )

    previous = Application.get_env(:ex_dns, :api)
    Application.put_env(:ex_dns, :api, token_path: token_path)

    on_exit(fn ->
      File.rm(token_path)
      PauseMode.unpause()

      case previous do
        nil -> Application.delete_env(:ex_dns, :api)
        v -> Application.put_env(:ex_dns, :api, v)
      end
    end)

    :ok
  end

  describe "dispatch/1 — help" do
    test "no args prints help" do
      assert {:ok, out} = CLI.dispatch([])
      assert IO.iodata_to_binary(out) =~ "exdns — operator CLI"
    end

    test "--help and help both work" do
      assert {:ok, _} = CLI.dispatch(["help"])
      assert {:ok, _} = CLI.dispatch(["--help"])
    end

    test "unknown command returns :error with the help text appended" do
      assert {:error, out} = CLI.dispatch(["zoinks"])
      msg = IO.iodata_to_binary(out)
      assert msg =~ "unknown command"
      assert msg =~ "exdns — operator CLI"
    end
  end

  describe "dispatch/1 — status" do
    test "renders identity + listeners + cluster + recursion + plugins" do
      assert {:ok, out} = CLI.dispatch(["status"])
      msg = IO.iodata_to_binary(out)
      assert msg =~ "ExDns "
      assert msg =~ "Identity:"
      assert msg =~ "Listeners:"
      assert msg =~ "Recursion:"
      assert msg =~ "Plugins:"
    end

    test "Plugins line reflects PauseMode" do
      PauseMode.pause(60)
      assert {:ok, out} = CLI.dispatch(["status"])
      assert IO.iodata_to_binary(out) =~ "paused"
    end
  end

  describe "dispatch/1 — token" do
    test "list is empty on a fresh store" do
      assert {:ok, out} = CLI.dispatch(["token", "list"])
      assert IO.iodata_to_binary(out) =~ "No tokens"
    end

    test "issue prints id + secret + role" do
      assert {:ok, out} = CLI.dispatch(["token", "issue", "--role", "viewer"])
      msg = IO.iodata_to_binary(out)
      assert msg =~ "Token issued"
      assert msg =~ "role:   viewer"
      assert msg =~ ~r/secret: \S+/
    end

    test "issue with scopes" do
      {:ok, _} =
        CLI.dispatch([
          "token",
          "issue",
          "--role",
          "zone_admin",
          "--scopes",
          "a.test,b.test"
        ])

      [record] = TokenStore.all()
      assert record["scopes"] == ["a.test", "b.test"]
      assert record["role"] == "zone_admin"
    end

    test "revoke is idempotent" do
      assert {:ok, _} = CLI.dispatch(["token", "revoke", "no-such-id"])
    end
  end

  describe "dispatch/1 — pause / unpause" do
    test "pause with default duration" do
      assert {:ok, out} = CLI.dispatch(["pause"])
      assert IO.iodata_to_binary(out) =~ "paused"
      assert PauseMode.paused?()
    end

    test "pause with `5m`" do
      assert {:ok, out} = CLI.dispatch(["pause", "5m"])
      assert IO.iodata_to_binary(out) =~ "300s"
      assert PauseMode.paused?()
    end

    test "pause with `until_unpaused`" do
      assert {:ok, out} = CLI.dispatch(["pause", "until_unpaused"])
      assert IO.iodata_to_binary(out) =~ "until manually unpaused"
      assert PauseMode.paused?()
    end

    test "unpause clears" do
      PauseMode.pause(60)
      assert PauseMode.paused?()

      assert {:ok, out} = CLI.dispatch(["unpause"])
      assert IO.iodata_to_binary(out) =~ "unpaused"
      refute PauseMode.paused?()
    end
  end

  describe "dispatch/1 — zone list" do
    test "renders the zones returned by Storage" do
      # Should at least not crash + return something.
      assert {:ok, _} = CLI.dispatch(["zone", "list"])
    end
  end
end
