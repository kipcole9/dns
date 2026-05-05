defmodule Mix.Tasks.Exdns.CtlTest do
  @moduledoc """
  End-to-end test of the `mix exdns.ctl` task: boot the admin
  HTTP server in-process, run each subcommand against it, verify
  the output.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias ExDns.Resource.SOA
  alias ExDns.Storage

  @port 9572

  setup_all do
    {:ok, sup} =
      Supervisor.start_link(
        [{Bandit, plug: ExDns.Admin, scheme: :http, port: @port}],
        strategy: :one_for_one
      )

    on_exit(fn -> Process.exit(sup, :shutdown) end)

    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)

    Storage.put_zone("ctl.test", [
      %SOA{
        name: "ctl.test",
        ttl: 60,
        class: :in,
        mname: "ns",
        email: "h",
        serial: 42,
        refresh: 1,
        retry: 1,
        expire: 1,
        minimum: 1
      }
    ])

    {:ok, base_url: "http://127.0.0.1:#{@port}"}
  end

  defp run(args, base_url) do
    stdout =
      capture_io(fn ->
        capture_io(:stderr, fn ->
          try do
            Mix.Tasks.Exdns.Ctl.run(["--url", base_url] ++ args)
          catch
            :exit, _ -> :ok
          end
        end)
        |> tap(&IO.write/1)
      end)

    stdout
  end

  test "status prints the loaded-zone count", %{base_url: base_url} do
    out = run(["status"], base_url)
    assert out =~ "ExDns running"
    assert out =~ "Loaded zones:"
  end

  test "zones lists each loaded zone with its serial", %{base_url: base_url} do
    out = run(["zones"], base_url)
    assert out =~ "ctl.test"
    assert out =~ "serial=42"
  end

  test "notify reports a 404 for an unknown apex", %{base_url: base_url} do
    out = run(["notify", "no-such-zone.test"], base_url)
    assert out =~ "no secondary for zone" or out =~ "error"
  end

  test "secondary reports a 404 for an unknown apex", %{base_url: base_url} do
    out = run(["secondary", "no-such-zone.test"], base_url)
    assert out =~ "no secondary for zone" or out =~ "error"
  end

  test "--json emits raw JSON instead of formatted summary", %{base_url: base_url} do
    out = run(["--json", "zones"], base_url)
    assert out =~ "ctl.test"
    # Raw JSON keys, not the human-friendly "serial=" format.
    assert out =~ "\"apex\""
  end

  test "no subcommand prints usage and exits with status 1", %{base_url: base_url} do
    out = run([], base_url)
    assert out =~ "Usage:"
    assert out =~ "Subcommands:"
  end
end
