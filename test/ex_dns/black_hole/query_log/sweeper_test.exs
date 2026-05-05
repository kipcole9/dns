defmodule ExDns.BlackHole.QueryLog.SweeperTest do
  @moduledoc """
  Verifies the query-log retention sweeper deletes old rows
  by age and by count, and is a no-op when both caps are nil.
  """

  use ExUnit.Case, async: false

  alias ExDns.BlackHole.QueryLog.Sweeper
  alias ExDns.BlackHole.Storage

  setup do
    path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_blackhole_sweeper_#{System.unique_integer([:positive])}.db"
      )

    previous = Application.get_env(:ex_dns, :black_hole)

    Application.put_env(:ex_dns, :black_hole,
      storage: {ExDns.BlackHole.Storage.SQLite, [path: path]}
    )

    :ok = Storage.init()

    on_exit(fn ->
      File.rm(path)
      File.rm(path <> "-wal")
      File.rm(path <> "-shm")

      case previous do
        nil -> Application.delete_env(:ex_dns, :black_hole)
        v -> Application.put_env(:ex_dns, :black_hole, v)
      end
    end)

    :ok
  end

  defp seed(rows) do
    Enum.each(rows, fn ts ->
      :ok =
        Storage.append_query_log(%{
          "ts_ns" => ts,
          "client_ip" => "1.2.3.4",
          "qname" => "x.test",
          "qtype" => :a,
          "decision" => :allow
        })
    end)
  end

  defp count_rows do
    %{rows: rows} = Storage.read_query_log(%{limit: 1000})
    length(rows)
  end

  test "by-age sweep keeps recent rows + drops older ones" do
    now = System.os_time(:nanosecond)
    one_hour = 3600 * 1_000_000_000

    seed([now - 2 * one_hour, now - 30 * 60 * 1_000_000_000, now])
    assert count_rows() == 3

    Application.put_env(
      :ex_dns,
      :black_hole,
      Application.get_env(:ex_dns, :black_hole) ++ [query_log_max_age_seconds: 3600]
    )

    {:ok, pid} = Sweeper.start_link([])
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    Sweeper.sweep_now()
    Process.sleep(50)

    # Two recent rows survive; the 2-hour-old one is gone.
    assert count_rows() == 2
  end

  test "by-count sweep keeps the N most-recent rows" do
    base = System.os_time(:nanosecond)
    seed(Enum.map(0..9, fn i -> base + i end))
    assert count_rows() == 10

    Application.put_env(
      :ex_dns,
      :black_hole,
      Application.get_env(:ex_dns, :black_hole) ++ [query_log_capacity: 5]
    )

    {:ok, pid} = Sweeper.start_link([])
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    Sweeper.sweep_now()
    Process.sleep(50)

    assert count_rows() == 5
  end

  test "no-op when both caps are nil" do
    seed([System.os_time(:nanosecond)])

    Application.put_env(
      :ex_dns,
      :black_hole,
      Application.get_env(:ex_dns, :black_hole) ++
        [query_log_capacity: nil, query_log_max_age_seconds: nil]
    )

    {:ok, pid} = Sweeper.start_link([])
    on_exit(fn -> if Process.alive?(pid), do: GenServer.stop(pid) end)

    Sweeper.sweep_now()
    Process.sleep(50)

    assert count_rows() == 1
  end
end
