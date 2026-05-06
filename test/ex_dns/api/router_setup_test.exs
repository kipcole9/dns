defmodule ExDns.API.RouterSetupTest do
  @moduledoc """
  First-run setup endpoints: `GET /api/v1/setup/status` and
  `POST /api/v1/setup/claim`.

  These are the only unauthenticated mutation endpoints in
  the API; they exist because the operator can't yet have a
  bearer token. The single-use bootstrap-code file is what
  gates them.
  """

  use ExUnit.Case, async: false
  use Plug.Test

  alias ExDns.API.{Router, TokenStore}
  alias ExDns.Bootstrap

  setup do
    bootstrap_path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_router_bootstrap_#{System.unique_integer([:positive])}.code"
      )

    token_path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_router_setup_tokens_#{System.unique_integer([:positive])}.json"
      )

    previous_bootstrap = Application.get_env(:ex_dns, :bootstrap)
    previous_api = Application.get_env(:ex_dns, :api)

    Application.put_env(:ex_dns, :bootstrap,
      enabled: true,
      code_path: bootstrap_path
    )

    Application.put_env(:ex_dns, :api, token_path: token_path)

    on_exit(fn ->
      File.rm(bootstrap_path)
      File.rm(token_path)

      case previous_bootstrap do
        nil -> Application.delete_env(:ex_dns, :bootstrap)
        v -> Application.put_env(:ex_dns, :bootstrap, v)
      end

      case previous_api do
        nil -> Application.delete_env(:ex_dns, :api)
        v -> Application.put_env(:ex_dns, :api, v)
      end
    end)

    :ok
  end

  describe "GET /api/v1/setup/status" do
    test "returns pending=false when no bootstrap file exists" do
      conn = call(:get, "/api/v1/setup/status")

      assert conn.status == 200
      assert decoded(conn) == %{"pending" => false}
    end

    test "returns pending=true after Bootstrap.generate!/0" do
      Bootstrap.generate!()

      conn = call(:get, "/api/v1/setup/status")

      assert conn.status == 200
      assert decoded(conn) == %{"pending" => true}
    end

    test "no auth header required" do
      conn = call(:get, "/api/v1/setup/status")
      assert conn.status == 200
    end
  end

  describe "POST /api/v1/setup/claim" do
    test "rejects when no bootstrap file is pending" do
      conn = call(:post, "/api/v1/setup/claim", %{"code" => "anything"})

      assert conn.status == 409
      assert decoded(conn) == %{"error" => "no bootstrap pending"}
    end

    test "rejects an invalid code (file preserved for retry)" do
      Bootstrap.generate!()

      conn = call(:post, "/api/v1/setup/claim", %{"code" => "nope"})

      assert conn.status == 403
      assert decoded(conn)["error"] =~ "invalid"

      assert Bootstrap.pending?()
    end

    test "issues a cluster_admin token on the right code, deletes the file" do
      code = Bootstrap.generate!()

      conn = call(:post, "/api/v1/setup/claim", %{"code" => code})

      assert conn.status == 201
      body = decoded(conn)

      assert body["role"] == "cluster_admin"
      assert body["scopes"] == ["*"]
      assert is_binary(body["secret"])
      assert is_binary(body["id"])

      refute Bootstrap.pending?()

      # Token works against the store.
      assert {:ok, _record} = TokenStore.find_by_secret(body["secret"])
    end

    test "returns disabled when the feature is off" do
      Bootstrap.generate!()
      Application.put_env(:ex_dns, :bootstrap, enabled: false, code_path: Bootstrap.path())

      conn = call(:post, "/api/v1/setup/claim", %{"code" => "anything"})

      assert conn.status == 404
      assert decoded(conn)["error"] =~ "disabled"
    end
  end

  defp call(method, path, body \\ nil) do
    conn =
      case method do
        :get -> conn(:get, path)
        :post -> conn(:post, path, ExDns.API.JSON.encode!(body || %{}))
      end

    conn
    |> put_req_header("content-type", "application/json")
    |> Router.call(Router.init([]))
  end

  defp decoded(conn) do
    case ExDns.API.JSON.Decoder.decode!(conn.resp_body) do
      m when is_map(m) -> m
      other -> other
    end
  end
end
