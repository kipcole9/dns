defmodule ExDns.Recursor.CacheNegativeTest do
  @moduledoc """
  Verifies RFC 2308 negative caching: NXDOMAIN entries serve every
  qtype for the cached name, NODATA entries match a single qtype,
  and the TTL is bounded by `min(SOA.minimum, SOA.ttl)`.
  """

  use ExUnit.Case, async: false

  alias ExDns.Recursor.Cache
  alias ExDns.Resource.{A, SOA}

  setup do
    Cache.init()
    Cache.clear()
    on_exit(fn -> Cache.clear() end)
    :ok
  end

  defp soa(opts \\ []) do
    %SOA{
      name: Keyword.get(opts, :name, "test"),
      ttl: Keyword.get(opts, :ttl, 3600),
      class: :in,
      mname: "ns",
      email: "h",
      serial: 1,
      refresh: 1,
      retry: 1,
      expire: 1,
      minimum: Keyword.get(opts, :minimum, 60)
    }
  end

  test "NXDOMAIN cached for one qtype hides the name from every qtype" do
    Cache.put_negative("ghost.test", :a, :nxdomain, soa())

    assert {:nxdomain, %SOA{}} = Cache.lookup("ghost.test", :a)
    assert {:nxdomain, %SOA{}} = Cache.lookup("ghost.test", :aaaa)
    assert {:nxdomain, %SOA{}} = Cache.lookup("ghost.test", :mx)
    assert {:nxdomain, %SOA{}} = Cache.lookup("ghost.test", :txt)
  end

  test "NODATA only matches the qtype that produced it" do
    Cache.put_negative("present.test", :aaaa, :nodata, soa())

    assert {:nodata, %SOA{}} = Cache.lookup("present.test", :aaaa)
    assert :miss = Cache.lookup("present.test", :a)
    assert :miss = Cache.lookup("present.test", :mx)
  end

  test "positive entry takes precedence over a stale-NODATA-shaped key" do
    Cache.put_negative("mixed.test", :a, :nodata, soa())
    Cache.put("mixed.test", :a, [%A{ipv4: {1, 2, 3, 4}}], 60)

    # The positive entry now occupies (mixed.test, :a).
    assert {:hit, [%A{ipv4: {1, 2, 3, 4}}]} = Cache.lookup("mixed.test", :a)
  end

  test "lookup returns NXDOMAIN even when a positive entry exists for a different qtype" do
    # Positive A — still queryable.
    Cache.put("mixed2.test", :a, [%A{ipv4: {1, 2, 3, 4}}], 60)
    # NXDOMAIN — should not interfere with the positive A entry,
    # since the positive lookup runs first.
    Cache.put_negative("mixed2.test", :ns, :nxdomain, soa())

    assert {:hit, [%A{}]} = Cache.lookup("mixed2.test", :a)
    # Other qtypes get the NXDOMAIN.
    assert {:nxdomain, %SOA{}} = Cache.lookup("mixed2.test", :aaaa)
  end

  test "negative TTL is bounded by min(SOA.minimum, SOA.ttl)" do
    # SOA.minimum = 5s; SOA.ttl = 60s — cache for 5s.
    Cache.put_negative("brief.test", :a, :nxdomain, soa(minimum: 5, ttl: 60))

    [{_, :nxdomain, _soa, expires_at, _orig_ttl}] =
      :ets.lookup(:ex_dns_recursor_cache, {"brief.test", :nxdomain})

    expected_max = :erlang.monotonic_time(:second) + 5
    assert expires_at <= expected_max + 1
  end

  test "negative TTL falls back to SOA.ttl when minimum > ttl" do
    Cache.put_negative("brief2.test", :a, :nxdomain, soa(minimum: 600, ttl: 30))

    [{_, :nxdomain, _, expires_at, _orig_ttl}] =
      :ets.lookup(:ex_dns_recursor_cache, {"brief2.test", :nxdomain})

    expected_max = :erlang.monotonic_time(:second) + 30
    assert expires_at <= expected_max + 1
  end

  test "case-insensitive lookup for negative entries" do
    Cache.put_negative("Mixed.Case.Test", :a, :nxdomain, soa())
    assert {:nxdomain, %SOA{}} = Cache.lookup("MIXED.case.test", :a)
  end

  test "telemetry hit event includes :kind for negative entries" do
    test_pid = self()

    :telemetry.attach(
      "cache-neg-test",
      [:ex_dns, :cache, :hit],
      fn _, _, metadata, _ -> send(test_pid, {:hit, metadata}) end,
      %{}
    )

    on_exit(fn -> :telemetry.detach("cache-neg-test") end)

    Cache.put_negative("tel.test", :a, :nxdomain, soa())
    Cache.lookup("tel.test", :a)

    assert_receive {:hit, %{kind: :nxdomain}}
  end
end
