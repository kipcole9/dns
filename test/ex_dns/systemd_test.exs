defmodule ExDns.SystemDTest do
  @moduledoc """
  Verifies sd_notify wire-format messages are sent over the
  Unix datagram socket pointed to by `$NOTIFY_SOCKET`.

  Acts as the receiving systemd by binding our own AF_UNIX
  datagram socket and reading the messages back.
  """

  use ExUnit.Case, async: false

  alias ExDns.SystemD

  doctest SystemD

  setup do
    socket_path =
      Path.join(System.tmp_dir!(), "exdns-sdnotify-#{System.unique_integer([:positive])}.sock")

    File.rm(socket_path)

    {:ok, listener} =
      :gen_udp.open(0, [:local, :binary, active: false, ifaddr: {:local, socket_path}])

    previous_notify = System.get_env("NOTIFY_SOCKET")
    previous_watchdog = System.get_env("WATCHDOG_USEC")
    System.put_env("NOTIFY_SOCKET", socket_path)
    System.delete_env("WATCHDOG_USEC")

    on_exit(fn ->
      :gen_udp.close(listener)
      File.rm(socket_path)

      case previous_notify do
        nil -> System.delete_env("NOTIFY_SOCKET")
        v -> System.put_env("NOTIFY_SOCKET", v)
      end

      case previous_watchdog do
        nil -> System.delete_env("WATCHDOG_USEC")
        v -> System.put_env("WATCHDOG_USEC", v)
      end
    end)

    {:ok, listener: listener, socket_path: socket_path}
  end

  defp recv_one(listener, timeout \\ 500) do
    case :gen_udp.recv(listener, 0, timeout) do
      {:ok, {_addr, _port, payload}} -> payload
      {:error, :timeout} -> nil
      {:error, reason} -> {:error, reason}
    end
  end

  test "notify_ready/0 sends READY=1 with a STATUS line", %{listener: listener} do
    :ok = SystemD.notify_ready()
    payload = recv_one(listener)
    assert payload =~ "READY=1"
    assert payload =~ "STATUS=Resolving DNS queries"
    assert payload =~ "MAINPID="
  end

  test "notify_stopping/0 sends STOPPING=1", %{listener: listener} do
    :ok = SystemD.notify_stopping()
    payload = recv_one(listener)
    assert payload =~ "STOPPING=1"
  end

  test "notify_watchdog/0 sends WATCHDOG=1", %{listener: listener} do
    :ok = SystemD.notify_watchdog()
    payload = recv_one(listener)
    assert payload == "WATCHDOG=1\n"
  end

  test "no NOTIFY_SOCKET → silent no-op" do
    System.delete_env("NOTIFY_SOCKET")
    assert :ok = SystemD.notify_ready()
    assert :ok = SystemD.notify_stopping()
    assert :ok = SystemD.notify_watchdog()
  end

  test "WATCHDOG_USEC arms a periodic pinger", %{listener: listener} do
    # 2_000_000 µs = 2s; pinger runs at 1s. Drain READY first.
    System.put_env("WATCHDOG_USEC", "2000000")
    :ok = SystemD.notify_ready()
    _ = recv_one(listener)

    # Wait for the first watchdog ping (interval is half of 2s,
    # plus our minimum-1000ms floor).
    payload = recv_one(listener, 2_500)
    assert payload == "WATCHDOG=1\n"
  end
end
