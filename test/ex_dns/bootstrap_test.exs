defmodule ExDns.BootstrapTest do
  @moduledoc """
  First-run bootstrap-code consumption.
  """

  use ExUnit.Case, async: false

  alias ExDns.Bootstrap
  alias ExDns.API.TokenStore

  setup do
    bootstrap_path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_bootstrap_#{System.unique_integer([:positive])}.code"
      )

    token_path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_tokens_bootstrap_#{System.unique_integer([:positive])}.json"
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

    {:ok, bootstrap_path: bootstrap_path, token_path: token_path}
  end

  describe "pending?/0" do
    test "false when no bootstrap file exists" do
      refute Bootstrap.pending?()
    end

    test "true once the file is written" do
      Bootstrap.generate!()
      assert Bootstrap.pending?()
    end

    test "false when the feature is disabled in config" do
      Bootstrap.generate!()
      Application.put_env(:ex_dns, :bootstrap, enabled: false, code_path: Bootstrap.path())
      refute Bootstrap.pending?()
    end
  end

  describe "generate!/0" do
    test "writes a 0600 file with a single-line code", %{bootstrap_path: path} do
      code = Bootstrap.generate!()

      assert is_binary(code) and byte_size(code) > 16
      assert File.exists?(path)
      assert {:ok, %File.Stat{mode: mode}} = File.stat(path)
      assert Bitwise.band(mode, 0o777) == 0o600
      assert String.trim(File.read!(path)) == code
    end

    test "generates a different code each call" do
      a = Bootstrap.generate!()
      b = Bootstrap.generate!()
      refute a == b
    end
  end

  describe "consume/1" do
    test "returns :not_pending when no file exists" do
      assert {:error, :not_pending} = Bootstrap.consume("anything")
    end

    test "returns :invalid_code on a wrong code" do
      _real = Bootstrap.generate!()
      assert {:error, :invalid_code} = Bootstrap.consume("definitely-wrong")

      # File is preserved on failure so the operator can retry.
      assert Bootstrap.pending?()
    end

    test "issues a cluster_admin token on the right code, deletes the file" do
      code = Bootstrap.generate!()

      assert {:ok, token} = Bootstrap.consume(code)
      assert token["role"] == "cluster_admin"
      assert token["scopes"] == ["*"]
      assert token["label"] =~ "bootstrap"
      assert is_binary(token["secret"]) and byte_size(token["secret"]) > 16

      # File gone, second consume rejected.
      refute Bootstrap.pending?()
      assert {:error, :not_pending} = Bootstrap.consume(code)

      # Token works against the API token store.
      assert {:ok, looked_up} = TokenStore.find_by_secret(token["secret"])
      assert looked_up["id"] == token["id"]
    end

    test "returns :disabled when the feature is off" do
      Bootstrap.generate!()
      Application.put_env(:ex_dns, :bootstrap, enabled: false, code_path: Bootstrap.path())

      assert {:error, :disabled} = Bootstrap.consume("anything")
    end
  end
end
