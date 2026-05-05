defmodule ExDns.RPZ.LoaderTest do
  @moduledoc """
  Verifies the RPZ loader reads zone files from `:rpz, :zones`,
  parses them, and installs the resulting rules into the
  Store.
  """

  use ExUnit.Case, async: false

  alias ExDns.RPZ.{Loader, Match, Rule, Store}

  setup do
    previous = Application.get_env(:ex_dns, :rpz)
    Store.clear()

    on_exit(fn ->
      Store.clear()

      case previous do
        nil -> Application.delete_env(:ex_dns, :rpz)
        v -> Application.put_env(:ex_dns, :rpz, v)
      end
    end)

    :ok
  end

  defp write_rpz(name, body) do
    path = Path.join(System.tmp_dir!(), "exdns-rpz-#{name}-#{System.unique_integer([:positive])}.zone")
    File.write!(path, body)
    on_exit(fn -> File.rm(path) end)
    path
  end

  test "no :zones configured → 0 rules, no error" do
    Application.put_env(:ex_dns, :rpz, zones: [])
    assert {:ok, 0} = Loader.load_all()
    assert [] = Store.rules()
  end

  # Note: the zone-file parser rejects bare "." CNAME targets,
  # so the fixtures here use synthesised-A actions (the most
  # common alternative shape). The parser-level coverage of
  # CNAME-with-special-target lives in `ExDns.RPZTest`.

  test "loads synthesise-trigger rules from a single file" do
    path =
      write_rpz("blocklist", """
      $ORIGIN rpz.test.
      $TTL 60
      @            IN SOA ns admin (1 60 60 60 60)
                   IN NS  ns
      evil.example IN A   0.0.0.0
      """)

    Application.put_env(:ex_dns, :rpz, zones: [path])

    assert {:ok, 1} = Loader.load_all()

    assert [%Rule{action: {:synthesise, _}}] = Store.rules()
  end

  test "concatenates rules from multiple files in listed order" do
    path1 =
      write_rpz("first", """
      $ORIGIN rpz1.test.
      $TTL 60
      @       IN SOA ns admin (1 60 60 60 60)
              IN NS  ns
      a.test  IN A   0.0.0.0
      """)

    path2 =
      write_rpz("second", """
      $ORIGIN rpz2.test.
      $TTL 60
      @       IN SOA ns admin (1 60 60 60 60)
              IN NS  ns
      b.test  IN A   0.0.0.0
      """)

    Application.put_env(:ex_dns, :rpz, zones: [path1, path2])

    assert {:ok, 2} = Loader.load_all()

    rules = Store.rules()
    assert {:match, _} = Match.find("a.test", rules)
    assert {:match, _} = Match.find("b.test", rules)
  end

  test "files matched by a glob are picked up" do
    dir = Path.join(System.tmp_dir!(), "exdns-rpz-glob-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)

    File.write!(Path.join(dir, "one.zone"), """
    $ORIGIN one.test.
    $TTL 60
    @   IN SOA ns admin (1 60 60 60 60)
        IN NS  ns
    bad IN A  0.0.0.0
    """)

    File.write!(Path.join(dir, "two.zone"), """
    $ORIGIN two.test.
    $TTL 60
    @   IN SOA ns admin (1 60 60 60 60)
        IN NS  ns
    bad IN A  0.0.0.0
    """)

    Application.put_env(:ex_dns, :rpz, zones: [Path.join(dir, "*.zone")])

    assert {:ok, 2} = Loader.load_all()
  end

  test "broken file logs but doesn't break loading other files" do
    good =
      write_rpz("good", """
      $ORIGIN ok.test.
      $TTL 60
      @         IN SOA ns admin (1 60 60 60 60)
                IN NS  ns
      blocked   IN A   0.0.0.0
      """)

    bad = write_rpz("broken", "this is not a zone file at all")

    Application.put_env(:ex_dns, :rpz, zones: [good, bad])

    assert {:ok, count} = Loader.load_all()
    assert count >= 1
  end
end
