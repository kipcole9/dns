defmodule ExDns.API.RouterActionsTest do
  @moduledoc """
  Tests the POST /api/v1/plugins/:slug/actions/:name route —
  auth (zone_admin role + plugin scope), dispatch to the
  plugin's `handle_action/2`, and the four error shapes.
  """

  use ExUnit.Case, async: false
  use Plug.Test

  alias ExDns.API.{Router, TokenStore}
  alias ExDns.Plugin.Registry

  defmodule SamplePlugin do
    @behaviour ExDns.Plugin
    @behaviour ExDns.Plugin.Action

    @impl ExDns.Plugin
    def metadata, do: %{slug: :sample, name: "Sample", version: "1"}

    @impl ExDns.Plugin.Action
    def handle_action("ok", params), do: {:ok, %{"echo" => params}}
    def handle_action("oops", _params), do: {:error, :something_failed}
  end

  defmodule QuietPlugin do
    @behaviour ExDns.Plugin

    @impl ExDns.Plugin
    def metadata, do: %{slug: :quiet, name: "Quiet", version: "1"}
  end

  setup do
    Registry.clear()
    Registry.register(SamplePlugin)
    Registry.register(QuietPlugin)

    path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_router_actions_#{System.unique_integer([:positive])}.json"
      )

    previous = Application.get_env(:ex_dns, :api)
    Application.put_env(:ex_dns, :api, token_path: path)

    on_exit(fn ->
      Registry.clear()
      File.rm(path)

      case previous do
        nil -> Application.delete_env(:ex_dns, :api)
        v -> Application.put_env(:ex_dns, :api, v)
      end
    end)

    {:ok, viewer} = TokenStore.issue(%{role: :viewer, scopes: []})
    {:ok, scoped} = TokenStore.issue(%{role: :zone_admin, scopes: ["plugin:sample"]})
    {:ok, unscoped} = TokenStore.issue(%{role: :zone_admin, scopes: []})

    {:ok,
     viewer: viewer["secret"],
     scoped: scoped["secret"],
     unscoped: unscoped["secret"]}
  end

  defp call(method, path, body, secret) do
    conn(method, path, :json.encode(body) |> IO.iodata_to_binary())
    |> put_req_header("content-type", "application/json")
    |> put_req_header("authorization", "Bearer " <> secret)
    |> Router.call(Router.init([]))
  end

  defp body(conn), do: :json.decode(conn.resp_body)

  test "200 + payload on success", %{scoped: token} do
    conn = call(:post, "/api/v1/plugins/sample/actions/ok", %{"k" => "v"}, token)
    assert conn.status == 200
    assert body(conn)["action"] == "ok"
    assert body(conn)["data"]["echo"] == %{"k" => "v"}
  end

  test "422 when plugin returns {:error, reason}", %{scoped: token} do
    conn = call(:post, "/api/v1/plugins/sample/actions/oops", %{}, token)
    assert conn.status == 422
  end

  test "404 for unknown plugin (caller must hold a matching scope)", %{unscoped: token} do
    # `unscoped` has zone_admin + empty scopes (granting all),
    # so the scope check passes; the route then resolves to a
    # 404 because no plugin exists at this slug.
    conn = call(:post, "/api/v1/plugins/missing/actions/ok", %{}, token)
    assert conn.status == 404
  end

  test "403 when caller's scopes are present but don't include the plugin", %{scoped: token} do
    # `scoped` has scopes ["plugin:sample"] only, so requests
    # for other plugins are denied at the scope check —
    # before the existence check fires.
    conn = call(:post, "/api/v1/plugins/missing/actions/ok", %{}, token)
    assert conn.status == 403
  end

  test "404 when plugin has no handle_action/2", %{scoped: token} do
    {:ok, quiet_token} =
      TokenStore.issue(%{role: :zone_admin, scopes: ["plugin:quiet"]})

    conn = call(:post, "/api/v1/plugins/quiet/actions/anything", %{}, quiet_token["secret"])
    assert conn.status == 404
    assert body(conn)["error"] == "plugin does not accept actions"
  end

  test "403 for viewer role", %{viewer: token} do
    conn = call(:post, "/api/v1/plugins/sample/actions/ok", %{}, token)
    assert conn.status == 403
  end

  test "zone_admin with empty scopes is global (matches existing zone-route behaviour)",
       %{unscoped: token} do
    conn = call(:post, "/api/v1/plugins/sample/actions/ok", %{}, token)
    assert conn.status == 200
  end
end
