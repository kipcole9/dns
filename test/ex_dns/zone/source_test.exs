defmodule ExDns.Zone.SourceTest do
  @moduledoc """
  Verifies wildcard expansion of the `:zones` config: literal
  paths pass through, glob patterns expand to all matching
  files, results are deduplicated and sorted, and end-to-end
  reload picks up files that match a glob.
  """

  use ExUnit.Case, async: false

  alias ExDns.Zone.Reload
  alias ExDns.Zone.Source

  setup do
    dir = Path.join(System.tmp_dir!(), "exdns-source-test-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)

    previous = Application.get_env(:ex_dns, :zones)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :zones)
        v -> Application.put_env(:ex_dns, :zones, v)
      end
    end)

    {:ok, dir: dir}
  end

  defp write_zone(dir, basename, serial) do
    path = Path.join(dir, basename)

    apex =
      basename
      |> Path.rootname()
      |> String.split(".")
      |> List.last()
      |> Kernel.<>(".test")

    File.write!(path, """
    $ORIGIN #{apex}.
    $TTL 60
    @  IN SOA ns admin (#{serial} 60 60 60 60)
       IN NS  ns
    ns IN A   192.0.2.1
    """)

    path
  end

  describe "expand/1" do
    test "literal paths pass through unchanged" do
      assert ["/literal.zone"] = Source.expand(["/literal.zone"])
    end

    test "wildcard expansion picks up matching files", %{dir: dir} do
      a = write_zone(dir, "alpha.zone", 1)
      b = write_zone(dir, "bravo.zone", 1)

      pattern = Path.join(dir, "*.zone")
      expanded = Source.expand([pattern])

      assert MapSet.new(expanded) == MapSet.new([a, b])
    end

    test "wildcard that matches nothing yields zero entries (not an error)", %{dir: dir} do
      assert [] = Source.expand([Path.join(dir, "*.nope")])
    end

    test "results are sorted + deduplicated", %{dir: dir} do
      a = write_zone(dir, "first.zone", 1)
      b = write_zone(dir, "second.zone", 1)

      # Listing the literal twice + the glob once must dedupe.
      pattern = Path.join(dir, "*.zone")
      result = Source.expand([a, b, pattern, a])

      assert result == Enum.sort([a, b])
    end

    test "literal + glob can be combined", %{dir: dir} do
      glob_match = write_zone(dir, "matched.zone", 1)
      literal = write_zone(dir, "explicit.zone", 1)

      pattern = Path.join(dir, "match*.zone")
      result = Source.expand([literal, pattern])

      assert MapSet.new(result) == MapSet.new([literal, glob_match])
    end

    test "non-binary entries are silently dropped" do
      assert [] = Source.expand([nil, 42, %{}])
    end
  end

  describe "Reload.reload_all/0 honours wildcard :zones entries" do
    test "loads every file matched by a glob", %{dir: dir} do
      write_zone(dir, "alpha.zone", 1)
      write_zone(dir, "bravo.zone", 1)

      Application.put_env(:ex_dns, :zones, [Path.join(dir, "*.zone")])

      assert {2, 0} = Reload.reload_all()
    end
  end
end
