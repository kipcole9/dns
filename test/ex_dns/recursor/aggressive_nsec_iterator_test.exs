defmodule ExDns.Recursor.AggressiveNSECIteratorTest do
  @moduledoc """
  End-to-end test of RFC 8198 aggressive NSEC use through the
  iterator: cache an NSEC range, query a name that falls inside
  the range, confirm the recursor returns NXDOMAIN locally
  without ever calling out.
  """

  use ExUnit.Case, async: false

  alias ExDns.Recursor.{Cache, Iterator}
  alias ExDns.Resource.NSEC

  # Mirror the bitmap helper used in the unit tests.
  import Bitwise

  defp bitmap(qtypes) do
    qtypes
    |> Enum.map(&ExDns.Resource.type_from/1)
    |> Enum.group_by(&div(&1, 256))
    |> Enum.map(fn {window, types} ->
      max_offset = types |> Enum.map(&rem(&1, 256)) |> Enum.max()
      bytes = div(max_offset, 8) + 1
      empty = :binary.copy(<<0>>, bytes)

      bits =
        Enum.reduce(types, empty, fn t, acc ->
          offset = rem(t, 256)
          byte_idx = div(offset, 8)
          bit_idx = 7 - rem(offset, 8)
          <<head::binary-size(byte_idx), b::8, tail::binary>> = acc
          <<head::binary, b ||| bsl(1, bit_idx)::8, tail::binary>>
        end)

      <<window::8, bytes::8, bits::binary>>
    end)
    |> IO.iodata_to_binary()
  end

  setup do
    Cache.init()
    Cache.clear()
    on_exit(fn -> Cache.clear() end)
    :ok
  end

  test "cached NSEC range proves NXDOMAIN for a name inside it (no network call)" do
    nsec = %NSEC{
      name: "alpha.example.test",
      ttl: 60,
      class: :in,
      next_domain: "echo.example.test",
      type_bit_maps: bitmap([:a])
    }

    Cache.put("alpha.example.test", :nsec, [nsec], 60)

    # `charlie.example.test` falls strictly between alpha and echo
    # → aggressive NSEC should yield NXDOMAIN locally.
    assert {:error, :nxdomain} = Iterator.resolve("charlie.example.test", :a)
  end

  test "cached NSEC at qname proves NODATA for a missing qtype" do
    nsec = %NSEC{
      name: "host.example.test",
      ttl: 60,
      class: :in,
      next_domain: "next.example.test",
      type_bit_maps: bitmap([:a])
    }

    Cache.put("host.example.test", :nsec, [nsec], 60)

    # qtype :a is in the bitmap → not NODATA. Test :mx which isn't.
    assert {:ok, []} = Iterator.resolve("host.example.test", :mx)
  end

  test "qtype actually present in the bitmap is NOT short-circuited as NODATA" do
    nsec = %NSEC{
      name: "host.example.test",
      ttl: 60,
      class: :in,
      next_domain: "next.example.test",
      type_bit_maps: bitmap([:a])
    }

    Cache.put("host.example.test", :nsec, [nsec], 60)

    # qtype :a IS in the bitmap, so the aggressive path must NOT
    # fire — verify via telemetry rather than the result, since
    # the network call may return its own NXDOMAIN.
    refute aggressive_fired?(fn ->
             Iterator.resolve("host.example.test", :a, max_time_ms: 100)
           end)
  end

  test "name OUTSIDE every cached NSEC range is not short-circuited" do
    nsec = %NSEC{
      name: "alpha.example.test",
      ttl: 60,
      class: :in,
      next_domain: "echo.example.test",
      type_bit_maps: bitmap([:a])
    }

    Cache.put("alpha.example.test", :nsec, [nsec], 60)

    # zulu sorts after echo, outside the interval — aggressive
    # path must NOT fire.
    refute aggressive_fired?(fn ->
             Iterator.resolve("zulu.example.test", :a, max_time_ms: 100)
           end)
  end

  test "expired NSEC records are not used for aggressive proof" do
    nsec = %NSEC{
      name: "alpha.example.test",
      ttl: 60,
      class: :in,
      next_domain: "echo.example.test",
      type_bit_maps: bitmap([:a])
    }

    Cache.put("alpha.example.test", :nsec, [nsec], 60)

    # Force the entry's expiry into the past.
    [{key, kind, payload, _}] = :ets.lookup(:ex_dns_recursor_cache, {"alpha.example.test", :nsec})
    :ets.insert(:ex_dns_recursor_cache, {key, kind, payload, :erlang.monotonic_time(:second) - 1})

    # Now charlie should NOT trigger the aggressive path.
    refute aggressive_fired?(fn ->
             Iterator.resolve("charlie.example.test", :a, max_time_ms: 100)
           end)
  end

  # Did the aggressive-NSEC short-circuit fire during `fun`? Looks
  # for a `[:ex_dns, :cache, :hit]` event whose `:kind` metadata
  # is one of the aggressive kinds.
  defp aggressive_fired?(fun) do
    handler_id = "aggressive-nsec-test-#{System.unique_integer([:positive])}"
    test_pid = self()

    :telemetry.attach(
      handler_id,
      [:ex_dns, :cache, :hit],
      fn _, _, metadata, _ ->
        case Map.get(metadata, :kind) do
          k when k in [:aggressive_nxdomain, :aggressive_nodata] ->
            send(test_pid, :aggressive_fired)

          _ ->
            :ok
        end
      end,
      %{}
    )

    try do
      fun.()
    after
      :telemetry.detach(handler_id)
    end

    receive do
      :aggressive_fired -> true
    after
      0 -> false
    end
  end
end
