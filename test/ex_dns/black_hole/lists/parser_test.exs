defmodule ExDns.BlackHole.Lists.ParserTest do
  @moduledoc """
  Golden tests covering the four blocklist formats: hosts,
  dnsmasq, AdGuard, plain-domain.
  """

  use ExUnit.Case, async: true

  alias ExDns.BlackHole.Lists.Parser

  doctest Parser

  test "hosts format" do
    body = """
    0.0.0.0 ads.example
    127.0.0.1 tracker.example
    192.168.1.1 not-a-block.example
    """

    assert Parser.parse(body) == ["ads.example", "tracker.example"]
  end

  test "dnsmasq format" do
    body = """
    address=/ads.example/0.0.0.0
    server=/tracker.example/
    """

    assert Parser.parse(body) == ["ads.example", "tracker.example"]
  end

  test "AdGuard format" do
    body = """
    ||ads.example^
    ||tracker.example^$important
    """

    assert Parser.parse(body) == ["ads.example", "tracker.example"]
  end

  test "plain domain format" do
    body = """
    ads.example
    tracker.example
    """

    assert Parser.parse(body) == ["ads.example", "tracker.example"]
  end

  test "comments + blanks are skipped" do
    body = """
    # this is a comment
    ! and this
    ads.example  # inline comment

       # indented comment
    """

    assert Parser.parse(body) == ["ads.example"]
  end

  test "wildcards survive untouched" do
    body = """
    *.ads.example
    """

    assert Parser.parse(body) == ["*.ads.example"]
  end

  test "mixed formats in one file all parse" do
    body = """
    # hosts entry
    0.0.0.0 a.example

    # dnsmasq entry
    address=/b.example/0.0.0.0

    # AdGuard
    ||c.example^

    # plain
    d.example
    """

    assert Parser.parse(body) == ["a.example", "b.example", "c.example", "d.example"]
  end

  test "domains are lower-cased + trailing-dot stripped" do
    assert Parser.parse("Bad.Example.") == ["bad.example"]
  end
end
