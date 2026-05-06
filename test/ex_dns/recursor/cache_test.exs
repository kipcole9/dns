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

  test "the table is capped at `:max_entries` (water-torture defence)" do
    previous = Application.get_env(:ex_dns, :recursor_cache)
    Application.put_env(:ex_dns, :recursor_cache, max_entries: 50)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :recursor_cache)
        v -> Application.put_env(:ex_dns, :recursor_cache, v)
      end
    end)

    Enum.each(1..200, fn i ->
      record = %A{name: "h#{i}.test", ttl: 3600, class: :in, ipv4: {1, 2, 3, 4}}
      Cache.put("h#{i}.test", :a, [record], 3600)
    end)

    # We push 200 entries with a cap of 50 — eviction must
    # have kicked in. Allow a slack of one eviction batch
    # (≈ cap * @evict_fraction = 5) on top of the cap.
    assert :ets.info(:ex_dns_recursor_cache, :size) <= 60
  end

  test "expired entries are dropped on lookup" do
    record = %A{ipv4: {1, 2, 3, 4}}
    Cache.put("short.lived", :a, [record], 60)
    # Force expiry by clamping the stored expiry to the past.
    [{key, kind, payload, _, original_ttl}] =
      :ets.lookup(:ex_dns_recursor_cache, {"short.lived", :a})

    :ets.insert(
      :ex_dns_recursor_cache,
      {key, kind, payload, :erlang.monotonic_time(:second) - 1, original_ttl}
    )

    assert :miss = Cache.lookup("short.lived", :a)
    assert Cache.size() == 0
  end
end
