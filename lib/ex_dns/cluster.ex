defmodule ExDns.Cluster do
  @moduledoc """
  Cluster membership and update-master election for ExDns.

  Each node in an ExDns cluster runs an instance of this GenServer.
  On boot it:

  1. Connects to the configured peer nodes (`:ex_dns, :cluster_nodes`).
  2. Participates in master election by attempting to register the
     `:ex_dns_update_master` name globally. The first node to register
     becomes the master; everyone else watches it and re-runs the
     election when it goes down.

  When a clustered storage backend is added (Khepri is the planned
  next step — see `plans/2026-05-02-storage-alternatives.md`), it will
  manage its own membership and replication; this module stays
  focused on the master-election + write-routing concern.

  ## API

  * `master/0` returns the pid of the current update master, or `nil`
    if none has been elected yet.
  * `master?/0` returns `true` if THIS node is the current master.
  * `master_node/0` returns the master's node, or `nil`.
  * `nodes/0` returns the list of cluster nodes (including ours).

  Updates to the storage backend should be routed through the master
  via `ExDns.Cluster.commit/1` (P10d).

  """

  use GenServer
  require Logger

  @global_name :ex_dns_update_master

  @doc false
  def child_spec(options) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [options]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end

  def start_link(options \\ []) do
    GenServer.start_link(__MODULE__, options, name: __MODULE__)
  end

  @doc "Returns the pid of the current update master, or nil."
  @spec master() :: pid() | nil
  def master do
    case :global.whereis_name(@global_name) do
      :undefined -> nil
      pid -> pid
    end
  end

  @doc "Returns true if THIS node currently holds the update-master role."
  @spec master?() :: boolean()
  def master? do
    case master() do
      nil -> false
      pid -> node(pid) == node()
    end
  end

  @doc "Returns the node hosting the update master, or nil."
  @spec master_node() :: node() | nil
  def master_node do
    case master() do
      nil -> nil
      pid -> node(pid)
    end
  end

  @doc "Returns the list of cluster nodes (including ours)."
  @spec nodes() :: [node()]
  def nodes do
    [node() | Node.list()]
  end

  @doc """
  Routes a write operation to the cluster's update master.

  When this node IS the master, `fun` is invoked locally. Otherwise the
  call is forwarded to the master via `GenServer.call`. Either way, the
  result is the value returned by `fun`.

  When clustering is disabled (no `ExDns.Cluster` GenServer in the
  supervision tree), the function is invoked locally without forwarding.

  ### Arguments

  * `fun` is a zero-arity function describing the write. It runs on
    the master node.

  * `timeout` is the maximum time, in milliseconds, to wait for the
    forwarded call. Defaults to 5000.

  ### Returns

  * The result of `fun.()`.

  """
  @spec commit((-> any()), non_neg_integer()) :: any()
  def commit(fun, timeout \\ 5_000) when is_function(fun, 0) do
    cond do
      not running?() -> fun.()
      master?() -> fun.()
      true -> forward_to_master(fun, timeout)
    end
  end

  defp running? do
    Process.whereis(__MODULE__) != nil
  end

  defp forward_to_master(fun, timeout) do
    case master() do
      nil ->
        # No master yet — fall back to local execution. This degrades
        # the cluster temporarily to "anyone can write" rather than
        # blocking; pick the safer behaviour for your deployment by
        # raising here instead if you prefer strict single-writer.
        fun.()

      pid ->
        GenServer.call(pid, {:commit, fun}, timeout)
    end
  end

  @doc """
  Test helper: returns `{:ran_on, node()}`. Used by the multi-node
  cluster test to verify that `commit/1` forwarded execution to the
  master. Public so it can be invoked across BEAM nodes via captured
  function reference (anonymous closures don't always survive
  cross-node serialisation).
  """
  @spec where_did_i_run() :: {:ran_on, node()}
  def where_did_i_run, do: {:ran_on, node()}

  @doc """
  Synchronously waits up to `timeout` ms for an update master to be
  elected. Useful in tests right after starting a cluster.
  """
  @spec await_master(non_neg_integer()) :: pid() | nil
  def await_master(timeout \\ 2_000) do
    deadline = monotonic() + timeout
    do_await_master(deadline)
  end

  defp do_await_master(deadline) do
    case master() do
      nil ->
        if monotonic() > deadline do
          nil
        else
          Process.sleep(20)
          do_await_master(deadline)
        end

      pid ->
        pid
    end
  end

  defp monotonic, do: :erlang.monotonic_time(:millisecond)

  # ----- GenServer ----------------------------------------------------

  @impl GenServer
  def init(options) do
    :net_kernel.monitor_nodes(true)
    peers = Keyword.get(options, :nodes, Application.get_env(:ex_dns, :cluster_nodes, []))

    Enum.each(peers, fn peer -> Node.connect(peer) end)

    # Optional libcluster integration: when the user has configured
    # `:libcluster_topologies`, start `Cluster.Supervisor` (if loaded)
    # so libcluster handles ongoing discovery. We do NOT depend on
    # libcluster at compile time; the symbol is resolved at runtime
    # via `Code.ensure_loaded?/1`.
    maybe_start_libcluster()

    state = %{master_ref: nil}
    send(self(), :elect)
    {:ok, state}
  end

  @impl GenServer
  def handle_info(:elect, state) do
    state = run_election(state)
    {:noreply, state}
  end

  def handle_info({:nodeup, node}, state) do
    Logger.info("ExDns.Cluster: node up #{inspect(node)}")
    {:noreply, state}
  end

  def handle_info({:nodedown, node}, state) do
    Logger.info("ExDns.Cluster: node down #{inspect(node)}")
    state = run_election(state)
    {:noreply, state}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, %{master_ref: ref} = state) do
    Logger.info("ExDns.Cluster: master process went down, re-running election")
    send(self(), :elect)
    {:noreply, %{state | master_ref: nil}}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl GenServer
  def handle_call({:commit, fun}, _from, state) do
    # Only the master should be receiving these. We trust the caller
    # but double-check defensively.
    result =
      if master?() do
        fun.()
      else
        case master() do
          nil -> fun.()
          pid -> GenServer.call(pid, {:commit, fun})
        end
      end

    {:reply, result, state}
  end

  # ----- election -----------------------------------------------------

  defp run_election(state) do
    case :global.register_name(@global_name, self()) do
      :yes ->
        Logger.info("ExDns.Cluster: this node (#{inspect(node())}) is now the update master")
        state

      :no ->
        case master() do
          nil ->
            # Race lost but no winner yet — retry shortly.
            Process.send_after(self(), :elect, 100)
            state

          pid when node(pid) != node() ->
            ref = Process.monitor(pid)
            %{state | master_ref: ref}

          _ours ->
            state
        end
    end
  end

  defp maybe_start_libcluster do
    topologies = Application.get_env(:ex_dns, :libcluster_topologies)

    cond do
      is_nil(topologies) ->
        :ok

      not Code.ensure_loaded?(Cluster.Supervisor) ->
        Logger.warning(
          "ExDns.Cluster: :libcluster_topologies is set but the libcluster dependency is not loaded; " <>
            "add `{:libcluster, \"~> 3.4\"}` to mix.exs"
        )

        :ok

      true ->
        case Cluster.Supervisor.start_link([topologies, [name: ExDns.ClusterSupervisor]]) do
          {:ok, _pid} -> :ok
          {:error, {:already_started, _pid}} -> :ok
          {:error, reason} -> Logger.error("ExDns.Cluster: libcluster failed: #{inspect(reason)}")
        end
    end
  end

end
