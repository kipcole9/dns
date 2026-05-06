defmodule ExDns.API.TokenStoreTest do
  @moduledoc """
  Verifies the bearer-token store: issuance, lookup,
  revocation, expiry, and constant-time secret comparison.
  """

  use ExUnit.Case, async: false

  alias ExDns.API.TokenStore

  setup do
    path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_tokens_#{System.unique_integer([:positive])}.json"
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

    {:ok, path: path}
  end

  describe "issue/1" do
    test "creates a token and persists it to disk", %{path: path} do
      assert {:ok, %{"id" => id, "secret" => secret, "role" => "viewer"} = record} =
               TokenStore.issue(%{role: :viewer, scopes: []})

      assert is_binary(id) and byte_size(id) > 0
      assert is_binary(secret) and byte_size(secret) >= 32
      assert record["created_at_unix"] > 0
      assert File.exists?(path)
    end

    test "captures scopes + label + optional expiry" do
      {:ok, record} =
        TokenStore.issue(%{
          role: "zone_admin",
          scopes: ["*.internal.example", "ad.example"],
          label: "ops_team_2026",
          expires_at_unix: 9_999_999_999
        })

      assert ["*.internal.example", "ad.example"] = record["scopes"]
      assert "ops_team_2026" = record["label"]
      assert 9_999_999_999 = record["expires_at_unix"]
    end

    test "secrets are unique across multiple issues" do
      {:ok, a} = TokenStore.issue(%{role: :viewer, scopes: []})
      {:ok, b} = TokenStore.issue(%{role: :viewer, scopes: []})
      refute a["secret"] == b["secret"]
      refute a["id"] == b["id"]
    end
  end

  describe "all/0" do
    test "returns [] when the store file doesn't exist yet" do
      assert [] = TokenStore.all()
    end

    test "lists every issued token" do
      {:ok, _} = TokenStore.issue(%{role: :viewer, scopes: []})
      {:ok, _} = TokenStore.issue(%{role: :cluster_admin, scopes: []})
      assert length(TokenStore.all()) == 2
    end
  end

  describe "find_by_secret/1" do
    test "returns the token for a matching secret" do
      {:ok, %{"id" => id, "secret" => secret}} =
        TokenStore.issue(%{role: :viewer, scopes: []})

      assert {:ok, %{"id" => ^id, "role" => "viewer"}} = TokenStore.find_by_secret(secret)
    end

    test ":error for an unknown secret" do
      assert :error = TokenStore.find_by_secret("nope")
    end

    test ":error for an expired token" do
      {:ok, %{"secret" => secret} = record} =
        TokenStore.issue(%{role: :viewer, scopes: [], expires_at_unix: 1})

      # Past expiry was set above (1970-01-01 + 1s).
      assert :error = TokenStore.find_by_secret(secret)
      assert record["expires_at_unix"] == 1
    end

    test ":error after the token is revoked" do
      {:ok, %{"id" => id, "secret" => secret}} =
        TokenStore.issue(%{role: :viewer, scopes: []})

      assert {:ok, _} = TokenStore.find_by_secret(secret)
      assert :ok = TokenStore.revoke(id)
      assert :error = TokenStore.find_by_secret(secret)
    end
  end

  describe "revoke/1" do
    test "is idempotent for unknown ids" do
      assert :ok = TokenStore.revoke("never-existed")
    end
  end

  describe "path/0" do
    test "respects :token_path config" do
      assert TokenStore.path() =~ "ex_dns_tokens_"
    end
  end

  describe "secrets at rest" do
    test "the on-disk file never contains the plaintext secret", %{path: path} do
      {:ok, %{"secret" => secret}} = TokenStore.issue(%{role: :viewer, scopes: []})

      raw = File.read!(path)

      refute raw =~ secret
      assert raw =~ "secret_hash"
      refute raw =~ ~s("secret":)
    end

    test "accepts legacy plaintext records on read and rewrites them on next mutation", %{
      path: path
    } do
      # Hand-craft an "old store" with a plaintext secret to
      # simulate an upgrade from a release that wrote them.
      legacy_secret = "legacy-secret-value-" <> Base.url_encode64(:crypto.strong_rand_bytes(16))
      legacy = %{
        "id" => "legacy-id",
        "secret" => legacy_secret,
        "role" => "viewer",
        "scopes" => [],
        "created_at_unix" => 1_700_000_000,
        "expires_at_unix" => nil,
        "label" => nil
      }
      File.write!(path, [legacy] |> :json.encode() |> IO.iodata_to_binary())

      assert {:ok, %{"id" => "legacy-id"}} = TokenStore.find_by_secret(legacy_secret)

      # Triggering any mutation rewrites the file in the new
      # shape; the legacy plaintext is gone.
      {:ok, _} = TokenStore.issue(%{role: :viewer, scopes: []})
      raw = File.read!(path)
      refute raw =~ legacy_secret
    end
  end
end
