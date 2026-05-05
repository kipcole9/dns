defmodule ExDns.API.AuthTest do
  @moduledoc """
  Verifies bearer-token extraction, role hierarchy, and scope
  glob matching for the `/api/v1` auth plug.
  """

  use ExUnit.Case, async: false
  use Plug.Test

  alias ExDns.API.Auth
  alias ExDns.API.TokenStore

  setup do
    path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_auth_tokens_#{System.unique_integer([:positive])}.json"
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

    :ok
  end

  defp issue!(role, scopes \\ []) do
    {:ok, record} = TokenStore.issue(%{role: role, scopes: scopes})
    record
  end

  defp request_with(token) do
    conn(:get, "/api/v1/zones")
    |> put_req_header("authorization", "Bearer " <> token)
  end

  describe "call/2 — bearer extraction" do
    test "valid bearer header → token assigned" do
      record = issue!(:viewer)

      result = Auth.call(request_with(record["secret"]), [])
      refute result.halted
      assert result.assigns[:exdns_token]["id"] == record["id"]
    end

    test "missing header → 401 + halted" do
      result = Auth.call(conn(:get, "/api/v1/zones"), [])
      assert result.status == 401
      assert result.halted
    end

    test "malformed header → 401" do
      result =
        conn(:get, "/api/v1/zones")
        |> put_req_header("authorization", "Token nope")
        |> Auth.call([])

      assert result.status == 401
    end

    test "unknown bearer secret → 401" do
      result =
        conn(:get, "/api/v1/zones")
        |> put_req_header("authorization", "Bearer no-such-token")
        |> Auth.call([])

      assert result.status == 401
    end

    test "lower-case 'bearer ' is also accepted" do
      record = issue!(:viewer)

      result =
        conn(:get, "/api/v1/zones")
        |> put_req_header("authorization", "bearer " <> record["secret"])
        |> Auth.call([])

      refute result.halted
    end
  end

  describe "require_role/2 — role hierarchy" do
    test "viewer cannot pass a require_role(:zone_admin) gate" do
      record = issue!(:viewer)

      result =
        request_with(record["secret"])
        |> Auth.call([])
        |> Auth.require_role(:zone_admin)

      assert result.status == 403
      assert result.halted
    end

    test "zone_admin passes :zone_admin and :viewer gates" do
      record = issue!(:zone_admin, ["example.test"])

      result = Auth.call(request_with(record["secret"]), [])
      refute Auth.require_role(result, :zone_admin).halted
      refute Auth.require_role(result, :viewer).halted
    end

    test "cluster_admin passes every gate" do
      record = issue!(:cluster_admin)
      result = Auth.call(request_with(record["secret"]), [])

      refute Auth.require_role(result, :cluster_admin).halted
      refute Auth.require_role(result, :zone_admin).halted
      refute Auth.require_role(result, :viewer).halted
    end
  end

  describe "require_scope/2 — zone glob matching" do
    test "empty scopes ⇒ token is global" do
      record = issue!(:zone_admin, [])

      result =
        request_with(record["secret"])
        |> Auth.call([])
        |> Auth.require_scope("anything.test")

      refute result.halted
    end

    test "exact match" do
      record = issue!(:zone_admin, ["example.test"])

      ok =
        request_with(record["secret"])
        |> Auth.call([])
        |> Auth.require_scope("example.test")

      refute ok.halted

      not_ok =
        request_with(record["secret"])
        |> Auth.call([])
        |> Auth.require_scope("other.test")

      assert not_ok.status == 403
    end

    test "wildcard glob matches subdomains" do
      record = issue!(:zone_admin, ["*.internal.example"])

      sub =
        request_with(record["secret"])
        |> Auth.call([])
        |> Auth.require_scope("mail.internal.example")

      refute sub.halted

      apex =
        request_with(record["secret"])
        |> Auth.call([])
        |> Auth.require_scope("internal.example")

      refute apex.halted

      outside =
        request_with(record["secret"])
        |> Auth.call([])
        |> Auth.require_scope("public.test")

      assert outside.status == 403
    end

    test "cluster_admin bypasses scope checks even when scopes are set" do
      record = issue!(:cluster_admin, ["only.example"])

      result =
        request_with(record["secret"])
        |> Auth.call([])
        |> Auth.require_scope("anything.test")

      refute result.halted
    end
  end
end
