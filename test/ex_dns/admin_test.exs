defmodule ExDns.AdminTest do
  @moduledoc """
  Verifies the admin HTTP API endpoints: list zones, reload all,
  secondary status, the bearer-token auth gate, and that
  unknown paths 404.
  """

  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn, only: [put_req_header: 3]

  alias ExDns.Resource.SOA
  alias ExDns.Storage

  setup do
    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)
    previous_admin = Application.get_env(:ex_dns, :admin)
    previous_zones = Application.get_env(:ex_dns, :zones)

    on_exit(fn ->
      Enum.each(Storage.zones(), &Storage.delete_zone/1)

      case previous_admin do
        nil -> Application.delete_env(:ex_dns, :admin)
        other -> Application.put_env(:ex_dns, :admin, other)
      end

      case previous_zones do
        nil -> Application.delete_env(:ex_dns, :zones)
        other -> Application.put_env(:ex_dns, :zones, other)
      end
    end)

    :ok
  end

  defp soa(name, serial) do
    %SOA{
      name: name,
      ttl: 60,
      class: :in,
      mname: "ns",
      email: "h",
      serial: serial,
      refresh: 1,
      retry: 1,
      expire: 1,
      minimum: 1
    }
  end

  defp call(conn) do
    ExDns.Admin.call(conn, ExDns.Admin.init([]))
  end

  test "GET /admin/zones returns currently loaded zones with serials" do
    Storage.put_zone("first.test", [soa("first.test", 7)])
    Storage.put_zone("second.test", [soa("second.test", 11)])

    conn = call(conn(:get, "/admin/zones"))
    assert conn.status == 200

    payload = :json.decode(conn.resp_body)
    apexes = for z <- payload["zones"], do: z["apex"]
    assert "first.test" in apexes
    assert "second.test" in apexes
  end

  test "POST /admin/zones/reload returns counts" do
    path = Path.join(System.tmp_dir!(), "admin-reload-#{System.unique_integer([:positive])}.zone")

    File.write!(path, """
    $ORIGIN admin.test.
    $TTL 60
    @  IN SOA ns admin (1 60 60 60 60)
       IN NS  ns
    ns IN A   192.0.2.1
    """)

    on_exit(fn -> File.rm(path) end)
    Application.put_env(:ex_dns, :zones, [path])

    conn = call(conn(:post, "/admin/zones/reload"))
    assert conn.status == 200

    payload = :json.decode(conn.resp_body)
    assert payload["loaded"] == 1
    assert payload["failed"] == 0
  end

  test "POST /admin/zones/:apex/notify returns 404 for an unknown apex" do
    conn = call(conn(:post, "/admin/zones/nope.test/notify"))
    assert conn.status == 404
  end

  test "GET /admin/secondaries/:apex returns 404 when no secondary is running" do
    conn = call(conn(:get, "/admin/secondaries/nope.test"))
    assert conn.status == 404
  end

  test "unknown path returns 404 JSON" do
    conn = call(conn(:get, "/admin/elsewhere"))
    assert conn.status == 404
    assert :json.decode(conn.resp_body)["error"] == "not found"
  end

  test "/healthz proxied through returns 200 ok" do
    conn = call(conn(:get, "/healthz"))
    assert conn.status == 200
    assert conn.resp_body =~ "ok"
  end

  describe "bearer-token authentication" do
    setup do
      Application.put_env(:ex_dns, :admin, enabled: true, bearer_token: "s3cret")
      :ok
    end

    test "401 without an Authorization header" do
      conn = call(conn(:get, "/admin/zones"))
      assert conn.status == 401
    end

    test "401 with the wrong token" do
      conn =
        conn(:get, "/admin/zones")
        |> put_req_header("authorization", "Bearer nope")
        |> call()

      assert conn.status == 401
    end

    test "200 with the correct token" do
      conn =
        conn(:get, "/admin/zones")
        |> put_req_header("authorization", "Bearer s3cret")
        |> call()

      assert conn.status == 200
    end
  end
end
