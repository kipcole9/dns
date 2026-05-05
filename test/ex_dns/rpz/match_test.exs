defmodule ExDns.RPZ.MatchTest do
  @moduledoc """
  Verifies the qname/wildcard matcher: exact-trigger
  precedence over wildcard, case + trailing-dot normalisation,
  source-order tie-breaking.
  """

  use ExUnit.Case, async: true

  alias ExDns.RPZ.{Match, Rule}

  doctest Match

  defp rule(trigger, action), do: %Rule{trigger: trigger, action: action, ttl: 60}

  test "exact qname match" do
    rules = [rule({:qname, "evil.test"}, :nxdomain)]
    assert {:match, %Rule{action: :nxdomain}} = Match.find("evil.test", rules)
  end

  test "wildcard match — same level" do
    rules = [rule({:wildcard, "evil.test"}, :nxdomain)]
    assert {:match, _} = Match.find("evil.test", rules)
  end

  test "wildcard match — deeper level" do
    rules = [rule({:wildcard, "evil.test"}, :nxdomain)]
    assert {:match, _} = Match.find("ads.evil.test", rules)
    assert {:match, _} = Match.find("a.b.c.evil.test", rules)
  end

  test "wildcard does NOT match unrelated names" do
    rules = [rule({:wildcard, "evil.test"}, :nxdomain)]
    assert :no_match = Match.find("good.test", rules)
  end

  test "exact qname trigger wins over wildcard at the same level" do
    rules = [
      rule({:wildcard, "evil.test"}, :nxdomain),
      rule({:qname, "host.evil.test"}, :passthru)
    ]

    assert {:match, %Rule{action: :passthru}} = Match.find("host.evil.test", rules)
  end

  test "case-insensitive matching on both sides" do
    rules = [rule({:qname, "EVIL.test"}, :nxdomain)]
    assert {:match, _} = Match.find("evil.TEST", rules)
  end

  test "trailing dots tolerated on both sides" do
    rules = [rule({:qname, "evil.test."}, :nxdomain)]
    assert {:match, _} = Match.find("evil.test", rules)
    assert {:match, _} = Match.find("evil.test.", rules)
  end

  test ":no_match when nothing fires" do
    rules = [rule({:qname, "evil.test"}, :nxdomain)]
    assert :no_match = Match.find("good.test", rules)
  end

  test "empty rule set returns :no_match" do
    assert :no_match = Match.find("anything.test", [])
  end

  test "rpz-ip and :other triggers are not consulted by this matcher" do
    rules = [
      rule({:rpz_ip, {10, 0, 0, 1}, 32}, :nxdomain),
      rule({:other, "rpz-nsdname-stem"}, :nxdomain)
    ]

    assert :no_match = Match.find("evil.test", rules)
  end

  test "first match wins on order ties at the same precedence level" do
    rules = [
      rule({:wildcard, "evil.test"}, :nxdomain),
      rule({:wildcard, "evil.test"}, :passthru)
    ]

    assert {:match, %Rule{action: :nxdomain}} = Match.find("ads.evil.test", rules)
  end
end
