defmodule ExDns.BlackHole.SetTest do
  @moduledoc """
  Tests for the compiled match set: classification of entries
  (exact / suffix / regex), label-walk on lookup, and the
  `:persistent_term` install/current dance.
  """

  use ExUnit.Case, async: false

  alias ExDns.BlackHole.Set, as: BHSet

  setup do
    BHSet.clear()
    on_exit(fn -> BHSet.clear() end)
    :ok
  end

  describe "compile/1 + match?/2" do
    test "exact-domain entries match the qname only" do
      set = BHSet.compile(["bad.example"])

      assert BHSet.match?(set, "bad.example")
      assert BHSet.match?(set, "Bad.Example.")
      refute BHSet.match?(set, "host.bad.example")
      refute BHSet.match?(set, "good.example")
    end

    test "wildcard `*.x` matches the apex AND every descendant" do
      set = BHSet.compile(["*.ads.example"])

      assert BHSet.match?(set, "ads.example")
      assert BHSet.match?(set, "tracker.ads.example")
      assert BHSet.match?(set, "deeply.nested.ads.example")
      refute BHSet.match?(set, "other.example")
    end

    test "regex entries (`/pattern/`) match when neither set hits" do
      set = BHSet.compile(["/^.*-ads\\..*$/"])

      assert BHSet.match?(set, "shop-ads.example")
      refute BHSet.match?(set, "shop.example")
    end

    test "blanks and unparseable regex are skipped" do
      set = BHSet.compile(["", "  ", "/[invalid/"])
      assert MapSet.size(set.exact) == 0
      assert MapSet.size(set.suffixes) == 0
      assert set.regex == []
    end
  end

  describe "install/1 + current/0" do
    test "current/0 returns an empty set when nothing is installed" do
      assert %{exact: %MapSet{}, suffixes: %MapSet{}, regex: []} = BHSet.current()
    end

    test "install/1 puts the set in :persistent_term" do
      set = BHSet.compile(["x.test", "*.y.test"])
      :ok = BHSet.install(set)

      current = BHSet.current()
      assert BHSet.match?(current, "x.test")
      assert BHSet.match?(current, "host.y.test")
    end
  end
end
