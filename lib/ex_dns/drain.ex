defmodule ExDns.Drain do
  @moduledoc """
  Coordinates graceful shutdown of the ExDns server.

  ## Why drain at all

  When the BEAM receives SIGTERM (k8s rolling deploy, systemd
  reload, `application:stop/1`), the supervisor would normally
  unceremoniously kill every child after a 5s timeout. That's fine
  for stateless workers but loses in-flight queries: a UDP packet
  that arrived 50ms before SIGTERM gets dropped on the floor, and
  any AXFR streaming over TCP is cut mid-record.

  This module flips a "draining" flag visible to the readiness
  probe (so load balancers stop routing here), closes listener
  sockets so no new queries arrive, then polls the resolver pool
  until every checked-out worker is back. Only then does the
  supervisor proceed with normal child shutdown.

  ## Wiring

  `ExDns.Application.prep_stop/1` calls `drain/1` before returning
  control to the supervisor. The drain is bounded by
  `:ex_dns, :drain, [timeout: 30_000]` (default 30s); after that
  shutdown proceeds even if some queries haven't completed.

  Liveness (`/healthz`) keeps returning 200 throughout the drain —
  the process is still alive, just quiescing.
  """

  require Logger

  @flag_key {__MODULE__, :draining}

  @doc """
  Returns whether the server is currently draining.

  ### Returns

  * `true` once `mark_draining/0` has been called.
  * `false` during normal operation.

  ### Examples

      iex> ExDns.Drain.draining?()
      false

  """
  @spec draining?() :: boolean()
  def draining? do
    case :persistent_term.get(@flag_key, false) do
      true -> true
      _ -> false
    end
  end

  @doc """
  Mark the server as draining. Visible immediately to every reader
  via `:persistent_term`.

  ### Returns

  * `:ok`.
  """
  @spec mark_draining() :: :ok
  def mark_draining do
    :persistent_term.put(@flag_key, true)
    :ok
  end

  @doc """
  Clear the draining flag. Used by tests; not normally called in
  production (a draining process is on its way down, not coming
  back).

  ### Returns

  * `:ok`.
  """
  @spec clear_draining() :: :ok
  def clear_draining do
    :persistent_term.erase(@flag_key)
    :ok
  end

  @doc """
  Run the drain procedure synchronously: flag the readiness probe,
  close listeners, wait for in-flight workers.

  ### Arguments

  * `options` is a keyword list:

  ### Options

  * `:timeout` — total drain budget in milliseconds. Defaults to
    `30_000`. After this elapses the function returns
    `{:partial, in_flight}` instead of `:ok`.

  * `:poll_interval` — milliseconds between worker-pool polls.
    Defaults to `100`.

  ### Returns

  * `:ok` when every worker checked back in within the budget.
  * `{:partial, count}` when the timeout elapsed with `count`
    queries still in flight.

  ### Examples

      iex> ExDns.Drain.clear_draining()
      iex> _ = ExDns.Drain.drain(timeout: 100)
      iex> ExDns.Drain.draining?()
      true

  """
  @spec drain(keyword()) :: :ok | {:partial, non_neg_integer()}
  def drain(options \\ []) do
    timeout = Keyword.get(options, :timeout, 30_000)
    poll_interval = Keyword.get(options, :poll_interval, 100)

    Logger.info("ExDns.Drain: starting drain (timeout=#{timeout}ms)")
    mark_draining()

    :telemetry.execute(
      [:ex_dns, :drain, :start],
      %{system_time: System.system_time()},
      %{timeout_ms: timeout}
    )

    # Closing the listener sockets stops new arrivals immediately.
    close_listener_sockets()

    deadline = System.monotonic_time(:millisecond) + timeout
    result = wait_for_idle(deadline, poll_interval)

    # Persistent journal backends (DETS) need to be flushed and
    # closed so pending writes make it to disk.
    flush_journal_storage()

    :telemetry.execute(
      [:ex_dns, :drain, :stop],
      %{duration: 0},
      %{result: drain_result(result)}
    )

    case result do
      :ok ->
        Logger.info("ExDns.Drain: drained cleanly")
        :ok

      {:partial, count} = partial ->
        Logger.warning("ExDns.Drain: drain timed out with #{count} queries still in flight")
        partial
    end
  end

  defp drain_result(:ok), do: :ok
  defp drain_result({:partial, _}), do: :partial

  # Best-effort close of every UDP and TCP listener. We swallow
  # errors because a listener that's already gone shouldn't block
  # the rest of the drain.
  defp close_listener_sockets do
    for inet_family <- [:inet, :inet6] do
      name = Module.concat(ExDns.Listener.UDP, inet_family)

      with pid when is_pid(pid) <- Process.whereis(name),
           {:ok, %{socket: socket}} <- safe_get_state(pid),
           true <- is_port(socket) do
        try do
          :gen_udp.close(socket)
        catch
          _, _ -> :ok
        end
      end
    end

    :ok
  end

  defp safe_get_state(pid) do
    try do
      {:ok, :sys.get_state(pid, 1_000)}
    catch
      _, _ -> :error
    end
  end

  defp wait_for_idle(deadline, poll_interval) do
    case in_flight() do
      0 ->
        :ok

      count ->
        if System.monotonic_time(:millisecond) >= deadline do
          {:partial, count}
        else
          Process.sleep(poll_interval)
          wait_for_idle(deadline, poll_interval)
        end
    end
  end

  defp flush_journal_storage do
    backend = ExDns.Zone.Journal.Storage.backend()

    if function_exported?(backend, :close, 0) do
      try do
        backend.close()
      catch
        _, _ -> :ok
      end
    end

    :ok
  end

  # Number of resolver workers currently checked OUT of the pool.
  # `poolboy.status/1` returns `{state_name, available, overflow,
  # monitors}`; "monitors" is the count of in-flight checkouts.
  defp in_flight do
    try do
      {_state, _avail, _overflow, monitors} = ExDns.Resolver.Supervisor.pool_status()
      monitors
    catch
      _, _ -> 0
    end
  end
end
