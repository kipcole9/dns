defmodule ExDns.Recursor.CacheTest do
  use ExUnit.Case, async: false

  alias ExDns.Recursor.Cache
  alias ExDns.Resource.A

  setup do
    Cache.init()
    Cache.clear()
    :ok
  end

  test "put + lookup round-trips an RRset" do
    record = %A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}
    Cache.put("example.com", :a, [record], 60)
    assert {:hit, [^record]} = Cache.lookup("example.com", :a)
  end

  test "lookup is case-insensitive" do
    record = %A{name: "Example.COM", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}
    Cache.put("Example.COM", :a, [record], 60)
    assert {:hit, _} = Cache.lookup("example.com", :a)
  end

  test "put with ttl=0 bypasses the cache" do
    Cache.put("never.cache", :a, [%A{ipv4: {1, 2, 3, 4}}], 0)
    assert :miss = Cache.lookup("never.cache", :a)
  end

  test "lookup returns :miss for an unknown key" do
    assert :miss = Cache.lookup("never.heard.of", :a)
  end

  test "expired entries are dropped on lookup" do
    record = %A{ipv4: {1, 2, 3, 4}}
    Cache.put("short.lived", :a, [record], 60)
    # Force expiry by clamping the stored expiry to the past.
    [{key, kind, payload, _}] = :ets.lookup(:ex_dns_recursor_cache, {"short.lived", :a})
    :ets.insert(:ex_dns_recursor_cache, {key, kind, payload, :erlang.monotonic_time(:second) - 1})

    assert :miss = Cache.lookup("short.lived", :a)
    assert Cache.size() == 0
  end
end
