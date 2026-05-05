defmodule ExDns.SystemD do
  @moduledoc """
  Minimal sd_notify(3) integration for running ExDns as a systemd
  Type=notify unit.

  systemd communicates with notify-style services through a Unix
  datagram socket whose path is in `$NOTIFY_SOCKET`. The service
  reports its readiness, status messages, and watchdog pings by
  writing newline-separated key=value pairs to that socket.

  This module covers the three messages worth wiring:

  * `READY=1` — sent once the supervision tree is up. systemd
    leaves the unit in `activating` state until it sees this.

  * `WATCHDOG=1` — sent periodically when `$WATCHDOG_USEC` is in
    the environment. systemd kills the unit if it stops arriving.

  * `STOPPING=1` — sent at drain start. Tells systemd "I'm
    quiescing on purpose" so it doesn't treat the slow exit as a
    fault.

  ## Wiring

  `notify_ready/0` is called from `ExDns.Application.start/2`
  after the supervisor comes up. `notify_stopping/0` is called
  from `ExDns.Drain.drain/1` at the start of the drain. The
  watchdog process is spawned by `notify_ready/0` only when the
  environment indicates systemd is actually watching.

  Outside systemd (no `$NOTIFY_SOCKET`), every function is a
  silent no-op so non-systemd deployments are unaffected.

  ## What's *not* here

  Socket activation (inheriting listening sockets via the
  `LISTEN_FDS` protocol) is a follow-up. It's straightforward but
  requires the listeners themselves to accept a pre-bound socket
  rather than binding their own — a small refactor of the UDP/TCP
  listener startup.
  """

  require Logger

  @doc """
  Send `READY=1` to systemd if `$NOTIFY_SOCKET` is set, and arm
  the watchdog process if `$WATCHDOG_USEC` is in the env.

  ### Returns

  * `:ok` — message dispatched (or no-op outside systemd).

  ### Examples

      iex> ExDns.SystemD.notify_ready()
      :ok

  """
  @spec notify_ready() :: :ok
  def notify_ready do
    case notify("READY=1\nSTATUS=Resolving DNS queries\nMAINPID=#{:os.getpid()}\n") do
      :ok ->
        maybe_arm_watchdog()
        :ok

      :no_socket ->
        :ok
    end
  end

  @doc """
  Send `STOPPING=1` to systemd. Called from the drain hook so
  systemd knows the slow exit is deliberate.

  ### Returns

  * `:ok`.
  """
  @spec notify_stopping() :: :ok
  def notify_stopping do
    case notify("STOPPING=1\nSTATUS=Draining...\n") do
      :ok -> :ok
      :no_socket -> :ok
    end
  end

  @doc """
  Send a single watchdog ping. Used by the per-interval pinger
  spawned in `maybe_arm_watchdog/0`.

  ### Returns

  * `:ok`.
  """
  @spec notify_watchdog() :: :ok
  def notify_watchdog do
    case notify("WATCHDOG=1\n") do
      :ok -> :ok
      :no_socket -> :ok
    end
  end

  # ----- internals --------------------------------------------------

  # Send a single sd_notify payload over the Unix datagram socket.
  # Returns `:ok` on successful send, `:no_socket` when the
  # NOTIFY_SOCKET env var is unset or the socket cannot be opened.
  defp notify(payload) when is_binary(payload) do
    case System.get_env("NOTIFY_SOCKET") do
      nil ->
        :no_socket

      "" ->
        :no_socket

      path ->
        send_unix_datagram(path, payload)
    end
  end

  defp send_unix_datagram(path, payload) do
    sockaddr = sockaddr_for(path)

    case :gen_udp.open(0, [:local, :binary, active: false]) do
      {:ok, socket} ->
        result = :gen_udp.send(socket, sockaddr, 0, payload)
        :gen_udp.close(socket)

        case result do
          :ok ->
            :ok

          {:error, reason} ->
            Logger.warning("ExDns.SystemD: sd_notify send failed: #{inspect(reason)}")
            :ok
        end

      {:error, reason} ->
        Logger.warning("ExDns.SystemD: cannot open AF_UNIX socket: #{inspect(reason)}")
        :ok
    end
  end

  # Linux abstract-namespace sockets are advertised as
  # "@/path/with/null/prefix"; the leading @ is replaced with a
  # NUL byte. Filesystem paths are passed through verbatim as a
  # local-address tuple.
  defp sockaddr_for("@" <> rest), do: {:local, <<0, rest::binary>>}
  defp sockaddr_for(path), do: {:local, path}

  # Spawn a process that writes WATCHDOG=1 at half the configured
  # interval (per sd_notify(3) recommendation: ping at WATCHDOG_USEC/2
  # so a single missed deadline doesn't kill the service).
  defp maybe_arm_watchdog do
    case System.get_env("WATCHDOG_USEC") do
      nil ->
        :ok

      "" ->
        :ok

      usec_str ->
        case Integer.parse(usec_str) do
          {usec, _} when usec > 0 ->
            interval_ms = max(1_000, div(usec, 2 * 1_000))

            Logger.info(
              "ExDns.SystemD: arming sd_watchdog at #{interval_ms}ms intervals"
            )

            spawn_link(fn -> watchdog_loop(interval_ms) end)
            :ok

          _ ->
            :ok
        end
    end
  end

  defp watchdog_loop(interval_ms) do
    Process.sleep(interval_ms)
    notify_watchdog()
    watchdog_loop(interval_ms)
  end
end
