defmodule ExDns.Resolver.PerZoneRouterTest do
  @moduledoc """
  Verifies the per-zone routing table: longest-suffix match,
  case-insensitivity, support for both keyword-list and map
  config shapes, and the `:passthru` no-match fallback.
  """

  use ExUnit.Case, async: false

  alias ExDns.Resolver.PerZoneRouter

  doctest PerZoneRouter

  setup do
    previous = Application.get_env(:ex_dns, :per_zone_forwarders)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :per_zone_forwarders)
        v -> Application.put_env(:ex_dns, :per_zone_forwarders, v)
      end
    end)

    :ok
  end

  describe "route/2" do
    test ":passthru when no zone matches" do
      assert :passthru =
               PerZoneRouter.route("nothing.test",
                 routes: %{"internal.example" => [{{10, 0, 0, 5}, 53}]}
               )
    end

    test "exact-zone match returns the upstreams" do
      routes = %{"internal.example" => [{{10, 0, 0, 5}, 53}]}

      assert {:forward, "internal.example", [{{10, 0, 0, 5}, 53}]} =
               PerZoneRouter.route("internal.example", routes: routes)
    end

    test "subdomain matches a parent zone" do
      routes = %{"internal.example" => [{{10, 0, 0, 5}, 53}]}

      assert {:forward, "internal.example", _} =
               PerZoneRouter.route("mail.internal.example", routes: routes)
    end

    test "longest matching suffix wins" do
      routes = %{
        "example" => [{{1, 1, 1, 1}, 53}],
        "internal.example" => [{{10, 0, 0, 5}, 53}]
      }

      assert {:forward, "internal.example", [{{10, 0, 0, 5}, 53}]} =
               PerZoneRouter.route("mail.internal.example", routes: routes)
    end

    test "lookup is case-insensitive on both qname and zone" do
      routes = %{"Internal.Example" => [{{10, 0, 0, 5}, 53}]}

      assert {:forward, "internal.example", _} =
               PerZoneRouter.route("Mail.INTERNAL.example", routes: routes)
    end

    test "trailing dots are normalised away" do
      routes = %{"internal.example." => [{{10, 0, 0, 5}, 53}]}

      assert {:forward, "internal.example", _} =
               PerZoneRouter.route("mail.internal.example.", routes: routes)
    end

    test "keyword-list config shape is also accepted" do
      routes = ["internal.example": [{{10, 0, 0, 5}, 53}]]

      assert {:forward, "internal.example", _} =
               PerZoneRouter.route("mail.internal.example", routes: routes)
    end

    test "non-matching shorter zone doesn't shadow a longer match" do
      routes = %{
        "ad.example" => [{{10, 0, 0, 6}, 53}],
        "internal.example" => [{{10, 0, 0, 5}, 53}]
      }

      assert {:forward, "ad.example", _} = PerZoneRouter.route("dc1.ad.example", routes: routes)
      assert :passthru = PerZoneRouter.route("public.example", routes: routes)
    end

    test "uses Application env when :routes option is not given" do
      Application.put_env(:ex_dns, :per_zone_forwarders, %{
        "corp.example" => [{{10, 0, 0, 5}, 53}]
      })

      assert {:forward, "corp.example", _} =
               PerZoneRouter.route("intranet.corp.example")
    end
  end

  describe "configured_routes/0" do
    test "returns an empty map when nothing is configured" do
      Application.delete_env(:ex_dns, :per_zone_forwarders)
      assert %{} = PerZoneRouter.configured_routes()
    end

    test "normalises the keys to lower-case, no-trailing-dot binaries" do
      Application.put_env(:ex_dns, :per_zone_forwarders, %{
        "Corp.Example." => [{{10, 0, 0, 5}, 53}]
      })

      assert %{"corp.example" => [{{10, 0, 0, 5}, 53}]} =
               PerZoneRouter.configured_routes()
    end
  end
end
