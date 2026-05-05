defmodule ExDns.Recursor.IteratorPrefetchStaleTest do
  @moduledoc """
  Verifies the iterator's wiring of two recursor-side behaviours:

  * Prefetch — a hit in the trailing-TTL window fires a
    background re-resolution.
  * Serve-stale (RFC 8767) — an upstream failure on a name
    whose entry is past TTL but inside the serve-stale window
    is answered from the stale cache.

  We don't drive the upstream resolver here; instead we
  pre-seed the cache and assert the in-process side-effects
  (telemetry + the in-flight prefetch table).
  """

  use ExUnit.Case, async: false

  alias ExDns.Recursor.{Cache, Iterator, Prefetch}
  alias ExDns.Resource.A

  setup do
    Cache.init()
    Cache.clear()
    Prefetch.init()
    Prefetch.clear()

    previous_stale = Application.get_env(:ex_dns, :recursor_serve_stale_ttl)
    previous_prefetch = Application.get_env(:ex_dns, :recursor_prefetch_enabled)

    on_exit(fn ->
      Cache.clear()
      Prefetch.clear()

      case previous_stale do
        nil -> Application.delete_env(:ex_dns, :recursor_serve_stale_ttl)
        v -> Application.put_env(:ex_dns, :recursor_serve_stale_ttl, v)
      end

      case previous_prefetch do
        nil -> Application.delete_env(:ex_dns, :recursor_prefetch_enabled)
        v -> Application.put_env(:ex_dns, :recursor_prefetch_enabled, v)
      end
    end)

    :ok
  end

  defp put_in_window(name, type, ttl \\ 100) do
    record = %A{name: name, ttl: ttl, class: :in, ipv4: {192, 0, 2, 1}}
    Cache.put(name, type, [record], ttl)

    [{key, kind, payload, _, original_ttl}] =
      :ets.lookup(:ex_dns_recursor_cache, {name, type})

    :ets.insert(
      :ex_dns_recursor_cache,
      {key, kind, payload, :erlang.monotonic_time(:second) + 5, original_ttl}
    )

    record
  end

  defp put_stale(name, type, age_secs) do
    record = %A{name: name, ttl: 60, class: :in, ipv4: {198, 51, 100, 7}}
    Cache.put(name, type, [record], 60)

    [{key, kind, payload, _, original_ttl}] =
      :ets.lookup(:ex_dns_recursor_cache, {name, type})

    :ets.insert(
      :ex_dns_recursor_cache,
      {key, kind, payload, :erlang.monotonic_time(:second) - age_secs, original_ttl}
    )

    record
  end

  describe "prefetch wiring" do
    test "hit on a fresh entry does not schedule a prefetch" do
      record = %A{name: "young.test", ttl: 600, class: :in, ipv4: {1, 2, 3, 4}}
      Cache.put("young.test", :a, [record], 600)

      test_pid = self()

      :telemetry.attach(
        "iter-prefetch-fresh",
        [:ex_dns, :recursor, :prefetch, :start],
        fn _, _, metadata, _ -> send(test_pid, {:prefetch_started, metadata}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach("iter-prefetch-fresh") end)

      assert {:ok, [^record]} = Iterator.resolve("young.test", :a)
      refute_receive {:prefetch_started, _}, 50
    end

    test "hit on an entry inside the prefetch window schedules a prefetch" do
      record = put_in_window("hot.test", :a)

      test_pid = self()

      :telemetry.attach(
        "iter-prefetch-hot",
        [:ex_dns, :recursor, :prefetch, :start],
        fn _, _, metadata, _ -> send(test_pid, {:prefetch_started, metadata}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach("iter-prefetch-hot") end)

      assert {:ok, [^record]} = Iterator.resolve("hot.test", :a)

      assert_receive {:prefetch_started, %{qname: "hot.test", qtype: :a}}, 200
    end
  end

  describe "maybe_serve_stale/3" do
    test "returns the stale records on a non-:nxdomain upstream error" do
      Application.put_env(:ex_dns, :recursor_serve_stale_ttl, 86_400)
      record = put_stale("legacy.test", :a, 30)

      test_pid = self()

      :telemetry.attach(
        "serve-stale-helper",
        [:ex_dns, :recursor, :serve_stale],
        fn _, measurements, metadata, _ ->
          send(test_pid, {:served_stale, measurements, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach("serve-stale-helper") end)

      assert {:ok, [^record]} = Iterator.maybe_serve_stale("legacy.test", :a, :timeout)

      assert_receive {:served_stale, %{count: 1, age_secs: age}, %{qname: "legacy.test"}}
      assert age >= 30
    end

    test "returns nil for :nxdomain (RFC says do not serve stale on NXDOMAIN)" do
      Application.put_env(:ex_dns, :recursor_serve_stale_ttl, 86_400)
      put_stale("legacy2.test", :a, 30)

      assert is_nil(Iterator.maybe_serve_stale("legacy2.test", :a, :nxdomain))
    end

    test "returns nil when no stale entry exists" do
      Application.put_env(:ex_dns, :recursor_serve_stale_ttl, 86_400)
      assert is_nil(Iterator.maybe_serve_stale("nothing.test", :a, :timeout))
    end

    test "returns nil when serve_stale_ttl is 0 (window disabled)" do
      Application.put_env(:ex_dns, :recursor_serve_stale_ttl, 0)
      put_stale("disabled.test", :a, 30)

      assert is_nil(Iterator.maybe_serve_stale("disabled.test", :a, :timeout))
    end
  end
end
