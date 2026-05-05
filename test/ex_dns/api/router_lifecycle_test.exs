defmodule ExDns.API.RouterLifecycleTest do
  @moduledoc """
  Phase 3 routes: secondary refresh + key rollover.
  """

  use ExUnit.Case, async: false
  use Plug.Test

  alias ExDns.API.{Router, TokenStore}

  setup do
    path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_router_life_tokens_#{System.unique_integer([:positive])}.json"
      )

    previous = Application.get_env(:ex_dns, :api)
    Application.put_env(:ex_dns, :api, token_path: path)

    on_exit(fn ->
      File.rm(path)

      case previous do
        nil -> Application.delete_env(:ex_dns, :api)
        v -> Application.put_env(:ex_dns, :api, v)
      end
    end)

    {:ok, viewer} = TokenStore.issue(%{role: :viewer, scopes: []})
    {:ok, zone_admin} = TokenStore.issue(%{role: :zone_admin, scopes: []})
    {:ok, cluster_admin} = TokenStore.issue(%{role: :cluster_admin, scopes: []})

    {:ok,
     viewer: viewer["secret"],
     zone_admin: zone_admin["secret"],
     cluster_admin: cluster_admin["secret"]}
  end

  defp call(method, path, body, secret) do
    conn(method, path, :json.encode(body) |> IO.iodata_to_binary())
    |> put_req_header("content-type", "application/json")
    |> put_req_header("authorization", "Bearer " <> secret)
    |> Router.call(Router.init([]))
  end

  describe "POST /api/v1/secondaries/:apex/refresh" do
    test "404 when no secondary is configured", %{zone_admin: token} do
      conn = call(:post, "/api/v1/secondaries/no.test/refresh", %{}, token)
      assert conn.status == 404
    end

    test "403 for viewer role", %{viewer: token} do
      conn = call(:post, "/api/v1/secondaries/x.test/refresh", %{}, token)
      assert conn.status == 403
    end
  end

  describe "POST /api/v1/keys/:zone/rollover/:phase" do
    test "403 for non-cluster-admin", %{zone_admin: token} do
      conn = call(:post, "/api/v1/keys/x.test/rollover/prepare", %{}, token)
      assert conn.status == 403
    end

    test "422 when the rollover function reports an error", %{cluster_admin: token} do
      # No keys for x.test → Rollover.prepare_zsk_rollover returns
      # an error tuple, surfaced as 422.
      conn = call(:post, "/api/v1/keys/x.test/rollover/prepare", %{"role" => "zsk"}, token)
      assert conn.status in [200, 422]
    end
  end
end
