defmodule ExDns.Recursor.CacheStalePrefetchTest do
  @moduledoc """
  Verifies the cache extensions backing serve-stale (RFC 8767)
  and prefetch-on-near-expiry: the new `lookup_stale/2` and
  `in_prefetch_window?/2` helpers.
  """

  use ExUnit.Case, async: false

  alias ExDns.Recursor.Cache
  alias ExDns.Resource.A

  setup do
    Cache.init()
    Cache.clear()

    previous = Application.get_env(:ex_dns, :recursor_serve_stale_ttl)

    on_exit(fn ->
      Cache.clear()

      case previous do
        nil -> Application.delete_env(:ex_dns, :recursor_serve_stale_ttl)
        v -> Application.put_env(:ex_dns, :recursor_serve_stale_ttl, v)
      end
    end)

    :ok
  end

  defp force_expired(name, type, age_secs) do
    [{key, kind, payload, _, original_ttl}] =
      :ets.lookup(:ex_dns_recursor_cache, {name, type})

    :ets.insert(
      :ex_dns_recursor_cache,
      {key, kind, payload, :erlang.monotonic_time(:second) - age_secs, original_ttl}
    )
  end

  describe "lookup_stale/2" do
    test "returns {:stale, records, age} for an expired entry inside the window" do
      Application.put_env(:ex_dns, :recursor_serve_stale_ttl, 86_400)
      record = %A{name: "stale.test", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}
      Cache.put("stale.test", :a, [record], 60)
      force_expired("stale.test", :a, 5)

      assert {:stale, [^record], age} = Cache.lookup_stale("stale.test", :a)
      assert age >= 5
    end

    test "returns :miss for an expired entry past the stale window" do
      Application.put_env(:ex_dns, :recursor_serve_stale_ttl, 0)
      record = %A{name: "evict.test", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}
      Cache.put("evict.test", :a, [record], 60)
      force_expired("evict.test", :a, 5)

      assert :miss = Cache.lookup_stale("evict.test", :a)
      # Past-window lookup also evicts.
      assert Cache.size() == 0
    end

    test "returns {:hit, records} for a still-fresh entry (same as lookup/2)" do
      record = %A{name: "fresh.test", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}
      Cache.put("fresh.test", :a, [record], 60)

      assert {:hit, [^record]} = Cache.lookup_stale("fresh.test", :a)
    end

    test "negative entries are not served stale" do
      Application.put_env(:ex_dns, :recursor_serve_stale_ttl, 86_400)

      soa = %ExDns.Resource.SOA{
        name: "test",
        ttl: 60,
        class: :in,
        mname: "ns",
        email: "h",
        serial: 1,
        refresh: 1,
        retry: 1,
        expire: 1,
        minimum: 60
      }

      Cache.put_negative("gone.test", :a, :nxdomain, soa)
      force_expired("gone.test", :nxdomain, 5)

      # Within the stale window the row is preserved, but
      # `lookup_stale/2` does not return a `:stale` variant for
      # negative entries.
      assert :miss = Cache.lookup_stale("gone.test", :a)
    end
  end

  describe "in_prefetch_window?/2" do
    test "false when nothing is cached" do
      refute Cache.in_prefetch_window?("nothing.test", :a)
    end

    test "false in the early portion of TTL" do
      record = %A{name: "young.test", ttl: 600, class: :in, ipv4: {1, 2, 3, 4}}
      Cache.put("young.test", :a, [record], 600)

      refute Cache.in_prefetch_window?("young.test", :a)
    end

    test "true once we cross the prefetch threshold" do
      record = %A{name: "old.test", ttl: 100, class: :in, ipv4: {1, 2, 3, 4}}
      Cache.put("old.test", :a, [record], 100)
      # Push the row's expires_at so that "now" is in the trailing
      # 10% window (95 of 100 seconds elapsed → 5 seconds remain).
      [{key, kind, payload, _, original_ttl}] =
        :ets.lookup(:ex_dns_recursor_cache, {"old.test", :a})

      :ets.insert(
        :ex_dns_recursor_cache,
        {key, kind, payload, :erlang.monotonic_time(:second) + 5, original_ttl}
      )

      assert Cache.in_prefetch_window?("old.test", :a)
    end

    test "false once the entry has actually expired" do
      record = %A{name: "expired.test", ttl: 100, class: :in, ipv4: {1, 2, 3, 4}}
      Cache.put("expired.test", :a, [record], 100)
      force_expired("expired.test", :a, 5)

      refute Cache.in_prefetch_window?("expired.test", :a)
    end

    test "configurable prefetch_fraction" do
      record = %A{name: "tunable.test", ttl: 100, class: :in, ipv4: {1, 2, 3, 4}}
      Cache.put("tunable.test", :a, [record], 100)
      # Push to "30 of 100 seconds remain" — outside the default
      # 10% window but inside a 0.5 (50%) window.
      [{key, kind, payload, _, original_ttl}] =
        :ets.lookup(:ex_dns_recursor_cache, {"tunable.test", :a})

      :ets.insert(
        :ex_dns_recursor_cache,
        {key, kind, payload, :erlang.monotonic_time(:second) + 30, original_ttl}
      )

      refute Cache.in_prefetch_window?("tunable.test", :a)
      assert Cache.in_prefetch_window?("tunable.test", :a, prefetch_fraction: 0.5)
    end
  end
end
