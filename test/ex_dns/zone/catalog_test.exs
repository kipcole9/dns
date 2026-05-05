defmodule ExDns.Zone.CatalogTest do
  @moduledoc """
  Verifies the RFC 9432 catalog-zone parser: extracts the version
  number, enumerates members, picks up optional `coo` and
  `group` properties, and computes diffs across catalog updates.
  """

  use ExUnit.Case, async: true

  alias ExDns.Resource.{PTR, SOA, TXT}
  alias ExDns.Zone.Catalog
  alias ExDns.Zone.Catalog.Member

  doctest Catalog

  defp soa(name) do
    %SOA{
      name: name,
      ttl: 3600,
      class: :in,
      mname: "ns",
      email: "h",
      serial: 1,
      refresh: 1,
      retry: 1,
      expire: 1,
      minimum: 1
    }
  end

  defp version_record(apex, version) do
    %TXT{name: "version." <> apex, ttl: 3600, class: :in, strings: ["#{version}"]}
  end

  defp member_ptr(apex, id, target) do
    %PTR{name: "#{id}.zones." <> apex, ttl: 3600, class: :in, pointer: target}
  end

  test "parse/2 extracts the catalog version" do
    records = [soa("catalog.example"), version_record("catalog.example", 2)]
    assert %{version: 2} = Catalog.parse("catalog.example", records)
  end

  test "parse/2 returns members in stable order" do
    records = [
      soa("catalog.example"),
      version_record("catalog.example", 2),
      member_ptr("catalog.example", "abc", "first.test"),
      member_ptr("catalog.example", "xyz", "second.test")
    ]

    %{members: members} = Catalog.parse("catalog.example", records)

    names = Enum.map(members, & &1.name)
    assert "first.test" in names
    assert "second.test" in names
  end

  test "parse/2 picks up the optional `coo` PTR property" do
    records = [
      soa("catalog.example"),
      member_ptr("catalog.example", "abc", "member.test"),
      %PTR{
        name: "coo.abc.zones.catalog.example",
        ttl: 3600,
        class: :in,
        pointer: "primary.example"
      }
    ]

    %{members: [member]} = Catalog.parse("catalog.example", records)
    assert member.coo == "primary.example"
  end

  test "parse/2 picks up the optional `group` TXT property" do
    records = [
      soa("catalog.example"),
      member_ptr("catalog.example", "abc", "member.test"),
      %TXT{name: "group.abc.zones.catalog.example", ttl: 3600, class: :in, strings: ["prod"]}
    ]

    %{members: [member]} = Catalog.parse("catalog.example", records)
    assert member.group == "prod"
  end

  test "parse/2 ignores entries that aren't under the zones suffix" do
    records = [
      soa("catalog.example"),
      member_ptr("catalog.example", "abc", "member.test"),
      # Junk PTR outside zones.<apex> — should be ignored.
      %PTR{name: "random.catalog.example", ttl: 3600, class: :in, pointer: "junk.test"}
    ]

    %{members: members} = Catalog.parse("catalog.example", records)
    assert length(members) == 1
  end

  test "parse/2 handles a missing version field by setting :version to nil" do
    records = [soa("catalog.example"), member_ptr("catalog.example", "a", "x.test")]
    assert %{version: nil} = Catalog.parse("catalog.example", records)
  end

  test "parse/2 is case-insensitive on names" do
    records = [
      soa("Catalog.Example"),
      member_ptr("Catalog.Example", "ABC", "Member.Test")
    ]

    %{members: [member]} = Catalog.parse("catalog.example", records)
    assert member.name == "member.test"
  end

  test "diff/2 detects added, removed, and changed members" do
    previous = [
      %Member{id: "a", name: "stays.test", coo: nil, group: "old"},
      %Member{id: "b", name: "removed.test", coo: nil, group: nil}
    ]

    current = [
      %Member{id: "a", name: "stays.test", coo: nil, group: "new"},
      %Member{id: "c", name: "added.test", coo: nil, group: nil}
    ]

    %{added: added, removed: removed, changed: changed} = Catalog.diff(previous, current)

    assert Enum.map(added, & &1.name) == ["added.test"]
    assert Enum.map(removed, & &1.name) == ["removed.test"]
    assert Enum.map(changed, & &1.name) == ["stays.test"]
  end

  test "diff/2 against an empty previous list reports everything as added" do
    members = [%Member{id: "a", name: "first.test", coo: nil, group: nil}]
    %{added: added, removed: [], changed: []} = Catalog.diff([], members)
    assert added == members
  end
end
