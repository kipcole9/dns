defmodule ExDns.Integration.ClusterTest do
  @moduledoc """
  Multi-node integration test for ExDns master election and update
  forwarding.

  Spins up three BEAM peer nodes via `:peer.start` (with stdio control,
  so they survive across setup_all → test process boundaries) and
  verifies that:

  * exactly one node is elected `ExDns.Cluster.master`
  * `Cluster.commit/1` invoked on a non-master node forwards to the
    master and runs there (we observe this by inspecting the node
    where the function actually executed)
  * killing the master triggers a re-election within ~3 seconds

  Storage replication-via-Mnesia is **not** verified here — multi-node
  Mnesia schema bootstrap is a follow-up (see plan P10f). The cluster
  semantics being tested here (election, forwarding) are the consensus
  layer; the underlying storage backend can be swapped later without
  affecting this test.

  Tagged `:integration` and `:cluster`.

  """

  use ExUnit.Case, async: false

  @moduletag :integration
  @moduletag :cluster

  setup_all do
    case ensure_distributed() do
      :ok ->
        peers = start_peers(3)
        configure_peers(peers)
        await_master_on(peers)

        on_exit(fn -> Enum.each(peers, &stop_peer/1) end)
        {:ok, %{peers: peers}}

      {:error, reason} ->
        IO.puts("\n[cluster test] cannot start distribution (#{inspect(reason)}), skipping")
        :ok
    end
  end

  test "election → commit forwarding → master failure → re-election",
       %{peers: peers} do
    # Step 1: exactly one node is elected and every peer agrees.
    masters =
      Enum.map(peers, fn peer -> pcall(peer.pid, ExDns.Cluster, :master_node, []) end)

    assert length(Enum.uniq(masters)) == 1
    [master] = Enum.uniq(masters)
    assert master in Enum.map(peers, & &1.node)

    # Step 2: commit/1 from a non-master forwards execution to the
    # master. Using a captured named function so the capture
    # serialises cleanly across nodes.
    non_master = Enum.find(peers, fn peer -> peer.node != master end)
    fun = pcall(non_master.pid, :erlang, :make_fun, [ExDns.Cluster, :where_did_i_run, 0])
    {:ran_on, executed_on} = pcall(non_master.pid, ExDns.Cluster, :commit, [fun])
    assert executed_on == master

    # Step 3: kill the master peer.
    survivors = Enum.reject(peers, fn peer -> peer.node == master end)
    master_peer = Enum.find(peers, fn peer -> peer.node == master end)
    stop_peer(master_peer)

    # Step 4: a new master is elected from the survivors within ~3 s.
    new_master = await_election_change(survivors, master, 3_000)
    assert new_master != nil
    assert new_master != master
    assert new_master in Enum.map(survivors, & &1.node)
  end

  # ----- helpers ------------------------------------------------------

  defp ensure_distributed do
    # EPMD must be running for BEAM distribution to work. On a fresh
    # shell it isn't; start it daemonised before attempting the kernel.
    if System.find_executable("epmd") do
      _ = System.cmd("epmd", ["-daemon"], stderr_to_stdout: true)
    end

    started =
      case Node.alive?() do
        true ->
          :ok

        false ->
          # Suffix with the OS PID so every fresh `mix test` run gets a
          # unique name and doesn't collide with stale EPMD entries
          # left over from previous runs.
          name = String.to_atom("ex_dns_test_runner_#{System.system_time(:nanosecond)}@127.0.0.1")
          case :net_kernel.start(name, %{name_domain: :longnames}) do
            {:ok, _} -> :ok
            {:error, {:already_started, _}} -> :ok
            {:error, reason} -> {:error, reason}
          end
      end

    case started do
      :ok ->
        :erlang.set_cookie(:ex_dns_cluster_test)
        :ok

      error ->
        error
    end
  end

  defp start_peers(count) do
    code_paths = :code.get_path()

    for index <- 1..count do
      name = String.to_atom("ex_dns_node_#{index}")

      {:ok, pid, node} =
        :peer.start(%{
          name: name,
          host: ~c"127.0.0.1",
          longnames: true,
          connection: :standard_io,
          args: [~c"-setcookie", ~c"ex_dns_cluster_test"]
        })

      :ok = pcall(pid, :code, :add_paths, [code_paths])
      true = pcall(pid, :erlang, :set_cookie, [:ex_dns_cluster_test])
      %{pid: pid, node: node, name: name}
    end
  end

  defp configure_peers(peers) do
    node_list = Enum.map(peers, & &1.node)

    Enum.each(peers, fn peer ->
      peer_others = node_list -- [peer.node]

      pcall(peer.pid, Application, :put_env, [:ex_dns, :listener_port, 0])
      pcall(peer.pid, Application, :put_env, [:ex_dns, :cluster, true])
      pcall(peer.pid, Application, :put_env, [:ex_dns, :cluster_nodes, peer_others])

      :ok =
        pcall(peer.pid, Application, :ensure_all_started, [:ex_dns]) |> normalize_started()
    end)
  end

  # peer.call uses the control channel (stdio); reliable across the
  # setup_all → test process boundary.
  defp pcall(pid, module, function, args) do
    :peer.call(pid, module, function, args, 10_000)
  end

  defp await_master_on(peers, timeout \\ 5_000) do
    deadline = monotonic() + timeout
    do_await_master_on(peers, deadline)
  end

  defp do_await_master_on(peers, deadline) do
    # Force `:global` to resolve any in-flight name conflicts before
    # we sample.
    Enum.each(peers, fn peer -> pcall(peer.pid, :global, :sync, []) end)

    masters =
      Enum.map(peers, fn peer -> pcall(peer.pid, ExDns.Cluster, :master_node, []) end)

    cond do
      Enum.any?(masters, &is_nil/1) ->
        if monotonic() > deadline do
          flunk("Not every peer agreed on a master within timeout: #{inspect(masters)}")
        else
          Process.sleep(100)
          do_await_master_on(peers, deadline)
        end

      length(Enum.uniq(masters)) == 1 ->
        :ok

      true ->
        if monotonic() > deadline do
          flunk("Peers disagree on master after timeout: #{inspect(masters)}")
        else
          Process.sleep(100)
          do_await_master_on(peers, deadline)
        end
    end
  end

  defp current_master(peers) do
    Enum.find_value(peers, fn peer ->
      case pcall(peer.pid, ExDns.Cluster, :master_node, []) do
        nil -> nil
        node -> node
      end
    end)
  end

  defp await_election_change(peers, old_master, timeout) do
    deadline = monotonic() + timeout
    do_await_election_change(peers, old_master, deadline)
  end

  defp do_await_election_change(peers, old_master, deadline) do
    case current_master(peers) do
      nil ->
        if monotonic() > deadline,
          do: nil,
          else: do_sleep_then_retry(peers, old_master, deadline)

      ^old_master ->
        if monotonic() > deadline,
          do: nil,
          else: do_sleep_then_retry(peers, old_master, deadline)

      new_master ->
        new_master
    end
  end

  defp do_sleep_then_retry(peers, old_master, deadline) do
    Process.sleep(100)
    do_await_election_change(peers, old_master, deadline)
  end

  defp stop_peer(peer) do
    try do
      :peer.stop(peer.pid)
    catch
      _, _ -> :ok
    end
  end

  defp normalize_started({:ok, _}), do: :ok
  defp normalize_started(:ok), do: :ok
  defp normalize_started({:error, {_app, {:already_started, _}}}), do: :ok
  defp normalize_started(other), do: other

  defp monotonic, do: :erlang.monotonic_time(:millisecond)
end
