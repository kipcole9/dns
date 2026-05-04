defmodule ExDns.ClusterTest do
  use ExUnit.Case, async: false

  alias ExDns.Cluster

  setup do
    # Start a fresh Cluster process per test so there's no leakage.
    safe_stop(Cluster)
    {:ok, _pid} = Cluster.start_link([])
    on_exit(fn -> safe_stop(Cluster) end)

    :ok
  end

  defp safe_stop(name) do
    case Process.whereis(name) do
      nil ->
        :ok

      pid ->
        try do
          GenServer.stop(pid)
        catch
          :exit, _ -> :ok
        end
    end
  end

  test "the lone node elects itself as master" do
    assert Cluster.await_master(1_000) != nil
    assert Cluster.master?()
    assert Cluster.master_node() == node()
  end

  test "commit/1 runs the function locally on the master" do
    assert Cluster.await_master(1_000)

    me = self()
    Cluster.commit(fn -> send(me, {:ran_on, node()}); :ok end)

    assert_receive {:ran_on, node}, 500
    assert node == node()
  end

  test "commit/1 returns the function's value" do
    assert Cluster.await_master(1_000)
    assert Cluster.commit(fn -> 42 end) == 42
  end

  test "commit/1 falls back to local execution when no Cluster is running" do
    GenServer.stop(Cluster)
    refute Process.whereis(Cluster)

    assert Cluster.commit(fn -> :still_works end) == :still_works
  end
end
