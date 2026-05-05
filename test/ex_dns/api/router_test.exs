defmodule ExDns.API.RouterTest do
  @moduledoc """
  End-to-end tests for the `/api/v1/*` Plug.Router. The router
  is exercised in-process via `Plug.Test` — no Bandit listener
  required.
  """

  use ExUnit.Case, async: false
  use Plug.Test

  alias ExDns.API.{Router, TokenStore}
  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage

  @apex "router-api.test"

  setup do
    Storage.init()

    Storage.put_zone(@apex, [
      %SOA{
        name: @apex,
        ttl: 60,
        class: :in,
        mname: "ns",
        email: "h",
        serial: 9,
        refresh: 60,
        retry: 60,
        expire: 60,
        minimum: 60
      },
      %A{name: "host.#{@apex}", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}},
      %A{name: "mail.#{@apex}", ttl: 60, class: :in, ipv4: {1, 2, 3, 5}}
    ])

    path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_router_tokens_#{System.unique_integer([:positive])}.json"
      )

    previous = Application.get_env(:ex_dns, :api)
    Application.put_env(:ex_dns, :api, token_path: path)

    on_exit(fn ->
      Storage.delete_zone(@apex)
      File.rm(path)

      case previous do
        nil -> Application.delete_env(:ex_dns, :api)
        v -> Application.put_env(:ex_dns, :api, v)
      end
    end)

    {:ok, viewer} = TokenStore.issue(%{role: :viewer, scopes: []})
    {:ok, viewer: viewer["secret"]}
  end

  defp call(method, path, secret \\ nil) do
    conn = conn(method, path)

    conn =
      if secret do
        put_req_header(conn, "authorization", "Bearer " <> secret)
      else
        conn
      end

    Router.call(conn, Router.init([]))
  end

  defp json_body(conn) do
    case :json.decode(conn.resp_body) do
      term -> term
    end
  end

  describe "auth" do
    test "missing bearer → 401" do
      conn = call(:get, "/api/v1/zones")
      assert conn.status == 401
    end

    test "bad bearer → 401" do
      conn = call(:get, "/api/v1/zones", "nope")
      assert conn.status == 401
    end
  end

  describe "GET /api/v1/health (no auth)" do
    test "200 ok for any caller" do
      conn = call(:get, "/api/v1/health")
      assert conn.status == 200
      assert conn.resp_body =~ "ok"
    end
  end

  describe "GET /api/v1/server" do
    test "returns identity, version, listeners, cluster", %{viewer: viewer} do
      conn = call(:get, "/api/v1/server", viewer)
      assert conn.status == 200

      body = json_body(conn)
      assert is_binary(body["identity"])
      assert is_binary(body["version"])
      assert is_list(body["listeners"])
      assert is_map(body["cluster"])
    end
  end

  describe "GET /api/v1/zones" do
    test "lists every zone in storage", %{viewer: viewer} do
      conn = call(:get, "/api/v1/zones", viewer)
      assert conn.status == 200

      body = json_body(conn)
      assert is_list(body["zones"])
      assert Enum.any?(body["zones"], fn z -> z["apex"] == @apex end)
    end
  end

  describe "GET /api/v1/zones/:apex" do
    test "returns details + per-type counts", %{viewer: viewer} do
      conn = call(:get, "/api/v1/zones/" <> @apex, viewer)
      assert conn.status == 200

      body = json_body(conn)
      assert body["apex"] == @apex
      assert body["serial"] == 9
      assert body["counts"]["A"] == 2
      assert body["counts"]["SOA"] == 1
    end

    test "404 for an unknown apex", %{viewer: viewer} do
      conn = call(:get, "/api/v1/zones/no-such.test", viewer)
      assert conn.status == 404
    end
  end

  describe "GET /api/v1/zones/:apex/records" do
    test "returns paginated record list with total", %{viewer: viewer} do
      conn = call(:get, "/api/v1/zones/" <> @apex <> "/records", viewer)
      assert conn.status == 200

      body = json_body(conn)
      assert body["total"] >= 3
      assert is_list(body["records"])
      assert Enum.any?(body["records"], fn r -> r["type"] == "A" end)
    end

    test "filters by ?type", %{viewer: viewer} do
      conn = call(:get, "/api/v1/zones/" <> @apex <> "/records?type=A", viewer)
      assert conn.status == 200

      body = json_body(conn)
      assert body["total"] == 2
      assert Enum.all?(body["records"], fn r -> r["type"] == "A" end)
    end

    test "filters by ?name substring", %{viewer: viewer} do
      conn = call(:get, "/api/v1/zones/" <> @apex <> "/records?name=mail", viewer)
      assert conn.status == 200

      body = json_body(conn)
      assert Enum.all?(body["records"], fn r -> String.contains?(r["name"], "mail") end)
    end

    test "respects ?limit + ?offset", %{viewer: viewer} do
      conn = call(:get, "/api/v1/zones/" <> @apex <> "/records?limit=1&offset=0", viewer)
      assert conn.status == 200

      body = json_body(conn)
      assert length(body["records"]) == 1
    end

    test "404 for an unknown apex", %{viewer: viewer} do
      conn = call(:get, "/api/v1/zones/missing.test/records", viewer)
      assert conn.status == 404
    end
  end

  describe "GET /api/v1/secondaries/:apex" do
    test "404 when the apex isn't a configured secondary", %{viewer: viewer} do
      conn = call(:get, "/api/v1/secondaries/" <> @apex, viewer)
      assert conn.status == 404
    end
  end

  describe "GET /api/v1/keys + plugins" do
    test "/keys returns a list (possibly empty)", %{viewer: viewer} do
      conn = call(:get, "/api/v1/keys", viewer)
      assert conn.status == 200
      assert is_list(json_body(conn)["keys"])
    end

    test "/plugins returns a list (possibly empty)", %{viewer: viewer} do
      conn = call(:get, "/api/v1/plugins", viewer)
      assert conn.status == 200
      assert is_list(json_body(conn)["plugins"])
    end
  end

  describe "GET /api/v1/metrics/summary" do
    test "returns the summary shape with default window", %{viewer: viewer} do
      conn = call(:get, "/api/v1/metrics/summary", viewer)
      assert conn.status == 200

      body = json_body(conn)
      assert body["window_seconds"] == 60
      assert is_map(body["queries"])
      assert is_map(body["cache_hits"])
    end

    test "respects ?window_seconds (clamped to [1, 3600])", %{viewer: viewer} do
      conn = call(:get, "/api/v1/metrics/summary?window_seconds=10", viewer)
      assert json_body(conn)["window_seconds"] == 10

      conn = call(:get, "/api/v1/metrics/summary?window_seconds=99999", viewer)
      assert json_body(conn)["window_seconds"] == 3600

      conn = call(:get, "/api/v1/metrics/summary?window_seconds=0", viewer)
      assert json_body(conn)["window_seconds"] == 1
    end
  end

  describe "404 fallback" do
    test "still requires auth (prevents route enumeration)" do
      conn = call(:get, "/api/v1/no/such/route")
      assert conn.status == 401
    end

    test "returns 404 with auth", %{viewer: viewer} do
      conn = call(:get, "/api/v1/no/such/route", viewer)
      assert conn.status == 404
    end
  end
end
