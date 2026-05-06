defmodule ExDns.Listener.PerIPCapTest do
  @moduledoc """
  Verifies the per-source-IP connection cap.
  """

  use ExUnit.Case, async: false

  alias ExDns.Listener.PerIPCap

  setup do
    previous = Application.get_env(:ex_dns, :per_ip_cap)

    Application.put_env(:ex_dns, :per_ip_cap, enabled: true, max_per_ip: 3)

    PerIPCap.reset()

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :per_ip_cap)
        v -> Application.put_env(:ex_dns, :per_ip_cap, v)
      end

      PerIPCap.reset()
    end)

    :ok
  end

  describe "acquire/1" do
    test "permits up to the cap, then refuses" do
      ip = {10, 0, 0, 1}

      assert :ok = PerIPCap.acquire(ip)
      assert :ok = PerIPCap.acquire(ip)
      assert :ok = PerIPCap.acquire(ip)
      assert {:error, :over_cap} = PerIPCap.acquire(ip)
    end

    test "different IPs have independent budgets" do
      ip1 = {10, 0, 0, 1}
      ip2 = {10, 0, 0, 2}

      Enum.each(1..3, fn _ -> assert :ok = PerIPCap.acquire(ip1) end)
      assert {:error, :over_cap} = PerIPCap.acquire(ip1)

      assert :ok = PerIPCap.acquire(ip2)
    end

    test "release/1 frees a slot" do
      ip = {10, 0, 0, 3}

      Enum.each(1..3, fn _ -> assert :ok = PerIPCap.acquire(ip) end)
      assert {:error, :over_cap} = PerIPCap.acquire(ip)

      PerIPCap.release(ip)
      assert :ok = PerIPCap.acquire(ip)
    end

    test "a refused acquire does NOT consume a slot" do
      ip = {10, 0, 0, 4}

      Enum.each(1..3, fn _ -> assert :ok = PerIPCap.acquire(ip) end)

      # Several refused attempts must not lock the IP out
      # past the natural release of held slots.
      Enum.each(1..10, fn _ -> assert {:error, :over_cap} = PerIPCap.acquire(ip) end)

      assert PerIPCap.count(ip) == 3
    end

    test "release at zero does not go negative" do
      ip = {10, 0, 0, 5}

      Enum.each(1..5, fn _ -> PerIPCap.release(ip) end)

      assert PerIPCap.count(ip) == 0
      assert :ok = PerIPCap.acquire(ip)
    end

    test "nil ip is always permitted" do
      assert :ok = PerIPCap.acquire(nil)
    end
  end

  describe "enabled: false" do
    test "every acquire passes" do
      Application.put_env(:ex_dns, :per_ip_cap, enabled: false)
      ip = {10, 0, 0, 6}

      Enum.each(1..100, fn _ -> assert :ok = PerIPCap.acquire(ip) end)
    end
  end
end
