defmodule ExDns.Cluster.QuorumTest do
  @moduledoc """
  Verifies the EKV-backed cluster's split-brain safety
  property: a node that can't reach quorum refuses CAS
  writes (returns `:no_quorum` / `:quorum_timeout`).

  Mechanism: spin up a second EKV instance (separate from
  the global `ExDns.EKV` one) configured with
  `cluster_size: 3` and peer addresses that don't exist.
  This is operationally equivalent to "we are the lone
  voter on the minority side of a permanent partition".

  The instance accepts eventual reads + LWW writes
  (cluster_size doesn't block those), but CAS writes
  fail.
  """

  use ExUnit.Case, async: false

  @name :ex_dns_quorum_test
  @data_dir Path.join(System.tmp_dir!(), "ex_dns_quorum_test")

  setup do
    File.rm_rf!(@data_dir)
    File.mkdir_p!(@data_dir)

    spec_options = [
      name: @name,
      data_dir: @data_dir,
      cluster_size: 3,
      mode: :member,
      # Don't sit in `wait_for_quorum` — let start_link return
      # so the test can exercise post-start behaviour with no
      # peers reachable (operationally identical to a permanent
      # minority partition).
      wait_for_quorum: false
    ]

    {:ok, sup} =
      Supervisor.start_link([EKV.child_spec(spec_options)],
        strategy: :one_for_one,
        name: :ex_dns_quorum_test_sup
      )

    on_exit(fn ->
      try do
        Supervisor.stop(sup)
      catch
        :exit, _ -> :ok
      end

      File.rm_rf!(@data_dir)
    end)

    :ok
  end

  test "eventual put + lookup work without quorum" do
    assert :ok = EKV.put(@name, "k", "v")
    # Local read is eventually-consistent — no quorum needed.
    assert {"v", _meta} = EKV.lookup(@name, "k")
  end

  test "CAS write fails when quorum is unreachable" do
    # `consistent: true` triggers the CAS path. With no
    # reachable peers, it must NOT silently succeed.
    result = EKV.put(@name, "cas-key", "v", consistent: true)

    assert match?({:error, _}, result),
           "expected CAS write to fail without quorum; got #{inspect(result)}"
  end

  test "update/3 (CAS read-modify-write) also fails without quorum" do
    result = EKV.update(@name, "cas-counter", fn _ -> 1 end)

    assert match?({:error, _}, result),
           "expected CAS update to fail without quorum; got #{inspect(result)}"
  end
end
