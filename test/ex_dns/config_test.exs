defmodule ExDns.ConfigTest do
  @moduledoc """
  Verifies the Elixir-data config loader: keyword-list shape,
  application of `:ex_dns` settings, missing-file handling,
  malformed-input rejection, and the `load_if_configured/0`
  hook used by Application.start/2.
  """

  use ExUnit.Case, async: false

  alias ExDns.Config

  setup do
    # Snapshot whatever config keys the tests touch so we can
    # restore them on exit.
    keys = ~w(refuse_any nsid rrl listener_port config_file transfer_acls)a
    snapshot = Enum.map(keys, fn k -> {k, Application.get_env(:ex_dns, k)} end)

    on_exit(fn ->
      System.delete_env("EXDNS_CONFIG")

      Enum.each(snapshot, fn
        {k, nil} -> Application.delete_env(:ex_dns, k)
        {k, v} -> Application.put_env(:ex_dns, k, v)
      end)
    end)

    :ok
  end

  defp write_config(contents) do
    path = Path.join(System.tmp_dir!(), "exdns-config-#{System.unique_integer([:positive])}.exs")
    File.write!(path, contents)
    on_exit(fn -> File.rm(path) end)
    path
  end

  describe "load/1" do
    test "applies a flat keyword list to Application env" do
      path = write_config("[refuse_any: true, listener_port: 5353]")

      assert {:ok, keys} = Config.load(path)
      assert :refuse_any in keys
      assert :listener_port in keys
      assert true == Application.get_env(:ex_dns, :refuse_any)
      assert 5353 == Application.get_env(:ex_dns, :listener_port)
    end

    test "round-trips nested keyword + map values" do
      path =
        write_config("""
        [
          nsid: [enabled: true, identifier: "ns1.test"],
          transfer_acls: %{"example.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}}
        ]
        """)

      assert {:ok, _} = Config.load(path)
      assert [enabled: true, identifier: "ns1.test"] = Application.get_env(:ex_dns, :nsid)

      assert %{"example.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}} =
               Application.get_env(:ex_dns, :transfer_acls)
    end

    test "missing file → {:error, :enoent}" do
      assert {:error, :enoent} = Config.load("/no/such/path.exs")
    end

    test "non-keyword-list contents → {:error, :not_a_keyword_list}" do
      path = write_config("123")
      assert {:error, :not_a_keyword_list} = Config.load(path)
    end

    test "syntactically invalid Elixir → {:error, {:eval_failed, msg}}" do
      path = write_config("[this is not valid")
      assert {:error, {:eval_failed, _msg}} = Config.load(path)
    end
  end

  describe "load!/1" do
    test "raises on failure" do
      assert_raise RuntimeError, ~r/ExDns.Config.load!/, fn ->
        Config.load!("/no/such/file.exs")
      end
    end

    test "returns the applied keys list on success" do
      path = write_config("[refuse_any: true]")
      assert [:refuse_any] = Config.load!(path)
    end
  end

  describe "load_if_configured/0" do
    test "no env var + no :config_file → :ok with no side effect" do
      Application.delete_env(:ex_dns, :config_file)
      System.delete_env("EXDNS_CONFIG")
      Application.delete_env(:ex_dns, :refuse_any)

      assert :ok = Config.load_if_configured()
      assert nil == Application.get_env(:ex_dns, :refuse_any)
    end

    test "EXDNS_CONFIG env var triggers load" do
      path = write_config("[refuse_any: true]")
      System.put_env("EXDNS_CONFIG", path)

      assert :ok = Config.load_if_configured()
      assert true == Application.get_env(:ex_dns, :refuse_any)
    end

    test ":config_file Application env triggers load when EXDNS_CONFIG unset" do
      path = write_config("[refuse_any: true]")
      System.delete_env("EXDNS_CONFIG")
      Application.put_env(:ex_dns, :config_file, path)

      assert :ok = Config.load_if_configured()
      assert true == Application.get_env(:ex_dns, :refuse_any)
    end

    test "EXDNS_CONFIG takes precedence over :config_file" do
      env_path = write_config("[refuse_any: true]")
      app_path = write_config("[refuse_any: false]")

      System.put_env("EXDNS_CONFIG", env_path)
      Application.put_env(:ex_dns, :config_file, app_path)

      Config.load_if_configured()
      assert true == Application.get_env(:ex_dns, :refuse_any)
    end

    test "broken config logs but doesn't crash startup" do
      path = write_config("[bad")
      System.put_env("EXDNS_CONFIG", path)

      assert :ok = Config.load_if_configured()
    end
  end
end
