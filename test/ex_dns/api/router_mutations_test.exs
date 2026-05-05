defmodule ExDns.API.RouterMutationsTest do
  @moduledoc """
  End-to-end tests for the Phase 2 mutating routes:
  POST/PATCH/DELETE on records, POST /reload.
  """

  use ExUnit.Case, async: false
  use Plug.Test

  alias ExDns.API.{Router, TokenStore}
  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage

  @apex "mut-api.test"

  setup do
    Storage.init()

    Storage.put_zone(@apex, [
      %SOA{
        name: @apex,
        ttl: 60,
        class: :in,
        mname: "ns",
        email: "h",
        serial: 1,
        refresh: 60,
        retry: 60,
        expire: 60,
        minimum: 60
      },
      %A{name: "host.#{@apex}", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}
    ])

    path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_router_mut_tokens_#{System.unique_integer([:positive])}.json"
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
    {:ok, zone_admin} = TokenStore.issue(%{role: :zone_admin, scopes: []})
    {:ok, viewer: viewer["secret"], zone_admin: zone_admin["secret"]}
  end

  defp call(method, path, body, secret) do
    conn(method, path, :json.encode(body) |> IO.iodata_to_binary())
    |> put_req_header("content-type", "application/json")
    |> put_req_header("authorization", "Bearer " <> secret)
    |> Router.call(Router.init([]))
  end

  defp call(method, path, secret) do
    conn(method, path)
    |> put_req_header("authorization", "Bearer " <> secret)
    |> Router.call(Router.init([]))
  end

  defp body(conn), do: :json.decode(conn.resp_body)

  describe "POST /api/v1/zones/:apex/records" do
    test "201 + record JSON on success", %{zone_admin: token} do
      payload = %{
        "name" => "added.#{@apex}",
        "type" => "A",
        "ttl" => 30,
        "class" => "IN",
        "rdata" => %{"ipv4" => "9.9.9.9"}
      }

      conn = call(:post, "/api/v1/zones/#{@apex}/records", payload, token)
      assert conn.status == 201

      record = body(conn)
      assert record["name"] == "added.#{@apex}"
      assert record["rdata"]["ipv4"] == "9.9.9.9"
    end

    test "403 for viewer role", %{viewer: token} do
      payload = %{"name" => "x.#{@apex}", "type" => "A", "rdata" => %{"ipv4" => "1.1.1.1"}}
      conn = call(:post, "/api/v1/zones/#{@apex}/records", payload, token)
      assert conn.status == 403
    end

    test "404 for unknown apex", %{zone_admin: token} do
      payload = %{"name" => "x.test", "type" => "A", "rdata" => %{"ipv4" => "1.1.1.1"}}
      conn = call(:post, "/api/v1/zones/missing.test/records", payload, token)
      assert conn.status == 404
    end

    test "422 for unknown type", %{zone_admin: token} do
      payload = %{"name" => "x.#{@apex}", "type" => "BOGUS", "rdata" => %{}}
      conn = call(:post, "/api/v1/zones/#{@apex}/records", payload, token)
      assert conn.status == 422
    end

    test "422 for invalid rdata shape", %{zone_admin: token} do
      payload = %{"name" => "x.#{@apex}", "type" => "A", "rdata" => %{"not" => "valid"}}
      conn = call(:post, "/api/v1/zones/#{@apex}/records", payload, token)
      assert conn.status == 422
    end
  end

  describe "PATCH /api/v1/zones/:apex/records/:id" do
    test "200 + new id when the rdata changes", %{zone_admin: token} do
      list_conn = call(:get, "/api/v1/zones/#{@apex}/records", token)
      [%{"id" => id} | _] =
        body(list_conn)["records"]
        |> Enum.filter(fn r -> r["type"] == "A" end)

      payload = %{
        "name" => "host.#{@apex}",
        "type" => "A",
        "ttl" => 60,
        "class" => "IN",
        "rdata" => %{"ipv4" => "5.6.7.8"}
      }

      conn = call(:patch, "/api/v1/zones/#{@apex}/records/#{id}", payload, token)
      assert conn.status == 200
      assert body(conn)["rdata"]["ipv4"] == "5.6.7.8"
      refute body(conn)["id"] == id
    end

    test "404 for unknown id", %{zone_admin: token} do
      payload = %{"name" => "x.#{@apex}", "type" => "A", "rdata" => %{"ipv4" => "1.1.1.1"}}
      conn = call(:patch, "/api/v1/zones/#{@apex}/records/no-such-id", payload, token)
      assert conn.status == 404
    end
  end

  describe "DELETE /api/v1/zones/:apex/records/:id" do
    test "204 when the record exists", %{zone_admin: token} do
      list_conn = call(:get, "/api/v1/zones/#{@apex}/records", token)
      [%{"id" => id} | _] =
        body(list_conn)["records"]
        |> Enum.filter(fn r -> r["type"] == "A" end)

      conn = call(:delete, "/api/v1/zones/#{@apex}/records/#{id}", token)
      assert conn.status == 204
    end

    test "404 for unknown id", %{zone_admin: token} do
      conn = call(:delete, "/api/v1/zones/#{@apex}/records/nope", token)
      assert conn.status == 404
    end
  end

  describe "POST /api/v1/zones/:apex/reload" do
    test "200 + {loaded, failed} counts", %{zone_admin: token} do
      conn = call(:post, "/api/v1/zones/#{@apex}/reload", %{}, token)
      assert conn.status == 200
      assert is_integer(body(conn)["loaded"])
      assert is_integer(body(conn)["failed"])
    end

    test "401 without auth" do
      conn =
        conn(:post, "/api/v1/zones/#{@apex}/reload", "{}")
        |> put_req_header("content-type", "application/json")
        |> Router.call(Router.init([]))

      assert conn.status == 401
    end
  end
end
