defmodule ExDns.ViewTest do
  @moduledoc """
  Verifies the View matcher: order-sensitive selection, OR
  semantics within a view, CIDR + TSIG-key + :any clauses, IPv4
  + IPv6, and map-form config normalisation.
  """

  use ExUnit.Case, async: false

  alias ExDns.View

  setup do
    previous = Application.get_env(:ex_dns, :views)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :views)
        other -> Application.put_env(:ex_dns, :views, other)
      end
    end)

    :ok
  end

  describe "select/2" do
    test "returns nil when no views are configured" do
      Application.delete_env(:ex_dns, :views)
      assert nil == View.select({127, 0, 0, 1}, nil)
    end

    test "returns the :any-fallback view when only that's configured" do
      Application.put_env(:ex_dns, :views, [
        %{name: "default", match: [:any], zones: ["zone1"]}
      ])

      assert %View{name: "default"} = View.select({1, 2, 3, 4}, nil)
    end

    test "matches by IPv4 CIDR" do
      Application.put_env(:ex_dns, :views, [
        %{name: "internal", match: [{:cidr, {{10, 0, 0, 0}, 8}}], zones: ["int"]},
        %{name: "external", match: [:any], zones: ["ext"]}
      ])

      assert %View{name: "internal"} = View.select({10, 5, 1, 1}, nil)
      assert %View{name: "external"} = View.select({1, 2, 3, 4}, nil)
    end

    test "matches by TSIG key name" do
      Application.put_env(:ex_dns, :views, [
        %{name: "admin", match: [{:tsig_key, "admin-key"}], zones: ["admin"]},
        %{name: "default", match: [:any], zones: ["pub"]}
      ])

      assert %View{name: "admin"} = View.select({1, 2, 3, 4}, "admin-key")
      assert %View{name: "default"} = View.select({1, 2, 3, 4}, nil)
      assert %View{name: "default"} = View.select({1, 2, 3, 4}, "wrong-key")
    end

    test "OR semantics within a single view's match list" do
      Application.put_env(:ex_dns, :views, [
        %{
          name: "trusted",
          match: [{:cidr, {{10, 0, 0, 0}, 8}}, {:tsig_key, "shared"}],
          zones: ["trusted"]
        },
        %{name: "default", match: [:any], zones: ["pub"]}
      ])

      # Either condition matches — view selected.
      assert %View{name: "trusted"} = View.select({10, 5, 1, 1}, nil)
      assert %View{name: "trusted"} = View.select({1, 2, 3, 4}, "shared")
      # Neither — falls through.
      assert %View{name: "default"} = View.select({1, 2, 3, 4}, "other-key")
    end

    test "first matching view wins (order is significant)" do
      Application.put_env(:ex_dns, :views, [
        %{name: "first", match: [{:cidr, {{10, 0, 0, 0}, 8}}], zones: ["a"]},
        %{name: "second", match: [{:cidr, {{10, 0, 0, 0}, 16}}], zones: ["b"]}
      ])

      # Both views CIDRs cover 10.0.0.1; the first registered wins.
      assert %View{name: "first"} = View.select({10, 0, 0, 1}, nil)
    end

    test "matches by IPv6 CIDR" do
      Application.put_env(:ex_dns, :views, [
        %{
          name: "v6-internal",
          match: [{:cidr, {{0xFD00, 0, 0, 0, 0, 0, 0, 0}, 8}}],
          zones: ["v6"]
        },
        %{name: "default", match: [:any], zones: ["pub"]}
      ])

      assert %View{name: "v6-internal"} =
               View.select({0xFD00, 0xABCD, 0, 0, 0, 0, 0, 1}, nil)

      assert %View{name: "default"} =
               View.select({0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, nil)
    end

    test "returns nil when no view matches and no :any fallback" do
      Application.put_env(:ex_dns, :views, [
        %{name: "internal", match: [{:cidr, {{10, 0, 0, 0}, 8}}], zones: ["int"]}
      ])

      assert nil == View.select({1, 2, 3, 4}, nil)
    end
  end

  describe "list/0" do
    test "returns the configured views in order" do
      Application.put_env(:ex_dns, :views, [
        %{name: "first", match: [:any], zones: ["a"]},
        %{name: "second", match: [:any], zones: ["b"]}
      ])

      assert [%View{name: "first"}, %View{name: "second"}] = View.list()
    end

    test "returns [] when nothing is configured" do
      Application.delete_env(:ex_dns, :views)
      assert [] = View.list()
    end
  end

  describe "view_matches?/3" do
    test "returns true for :any" do
      view = %View{name: "default", match: [:any], zones: []}
      assert View.view_matches?(view, {1, 2, 3, 4}, nil)
    end

    test "returns false for an empty match list" do
      view = %View{name: "no-match", match: [], zones: []}
      refute View.view_matches?(view, {1, 2, 3, 4}, nil)
    end
  end

  describe "config normalisation" do
    test "accepts both map and View struct forms" do
      Application.put_env(:ex_dns, :views, [
        %View{name: "struct-form", match: [:any], zones: ["a"]},
        %{name: "map-form", match: [:any], zones: ["b"]}
      ])

      assert [
               %View{name: "struct-form"},
               %View{name: "map-form"}
             ] = View.list()
    end
  end
end
