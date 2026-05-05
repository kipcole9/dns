defmodule ExDns.EKVTest do
  @moduledoc """
  Smoke test for the `ExDns.EKV` wrapper. The Application
  supervisor starts EKV at boot, so all subsystems can rely
  on it being available.
  """

  use ExUnit.Case, async: false

  setup do
    # Clean before each test so we don't depend on previous
    # tests' on_exit hooks having run yet.
    cleanup()
    on_exit(&cleanup/0)
    :ok
  end

  defp cleanup do
    ["ekv-test/", "ekv-test-2/"]
    |> Enum.each(fn prefix ->
      ExDns.EKV.scan(prefix)
      |> Enum.each(fn {key, _value, _meta} -> ExDns.EKV.delete(key) end)
    end)
  end

  test "put + lookup round-trip" do
    assert :ok = ExDns.EKV.put("ekv-test/k1", %{hello: "world"})
    assert %{hello: "world"} = ExDns.EKV.lookup("ekv-test/k1")
  end

  test "lookup returns nil for missing keys" do
    assert is_nil(ExDns.EKV.lookup("ekv-test/no-such-key"))
  end

  test "delete removes the key" do
    :ok = ExDns.EKV.put("ekv-test/del", "x")
    :ok = ExDns.EKV.delete("ekv-test/del")
    assert is_nil(ExDns.EKV.lookup("ekv-test/del"))
  end

  test "scan returns matching prefix entries" do
    # Use a test-scoped prefix so leftover CAS-managed keys
    # from other tests (which can't be cheaply deleted)
    # don't pollute the result.
    prefix = "ekv-scantest-#{System.unique_integer([:positive])}/"
    :ok = ExDns.EKV.put(prefix <> "a", 1)
    :ok = ExDns.EKV.put(prefix <> "b", 2)
    :ok = ExDns.EKV.put("ekv-other/x", 99)

    keys =
      prefix
      |> ExDns.EKV.scan()
      |> Enum.map(fn {k, _v, _m} -> k end)
      |> Enum.sort()

    assert keys == [prefix <> "a", prefix <> "b"]

    ExDns.EKV.delete(prefix <> "a")
    ExDns.EKV.delete(prefix <> "b")
    ExDns.EKV.delete("ekv-other/x")
  end

  test "update is CAS-safe (single-node, cluster_size: 1)" do
    # Once a key is touched by update/3 it becomes CAS-managed
    # — subsequent writes MUST also go through update. Use a
    # unique key per test run so re-runs aren't affected by
    # the sticky state.
    key = "ekv-test/counter-#{System.unique_integer([:positive])}"

    assert {:ok, 1, _vsn} =
             ExDns.EKV.update(key, fn n -> (n || 0) + 1 end)

    assert 1 = ExDns.EKV.lookup(key)
  end
end
