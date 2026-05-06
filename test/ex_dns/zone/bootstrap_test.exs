defmodule ExDns.Zone.BootstrapTest do
  @moduledoc """
  Verifies the "host my domain" zone-creation helper.
  """

  use ExUnit.Case, async: false

  alias ExDns.Storage
  alias ExDns.Zone.Bootstrap

  setup do
    dir =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_zone_bootstrap_#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(dir)
    Storage.init()

    on_exit(fn ->
      File.rm_rf!(dir)
      Storage.delete_zone("ex.test")
      Storage.delete_zone("with-v6.test")
    end)

    {:ok, dir: dir}
  end

  describe "create_authoritative_zone/2" do
    test "writes a v4-only zone and loads it into storage", %{dir: dir} do
      assert {:ok, %{path: path, apex: "ex.test"}} =
               Bootstrap.create_authoritative_zone("ex.test",
                 dir: dir,
                 ns_ip: "192.0.2.10"
               )

      assert File.exists?(path)
      text = File.read!(path)

      assert text =~ "$ORIGIN ex.test."
      assert text =~ "ns1 IN A    192.0.2.10"
      refute text =~ "AAAA"

      # Zone is loaded into Storage.
      assert "ex.test" in Storage.zones()
    end

    test "includes IPv6 glue when :ns_ipv6 is given", %{dir: dir} do
      assert {:ok, %{path: path}} =
               Bootstrap.create_authoritative_zone("with-v6.test",
                 dir: dir,
                 ns_ip: "192.0.2.20",
                 ns_ipv6: "2001:db8::20"
               )

      text = File.read!(path)
      assert text =~ "ns1 IN AAAA 2001:db8::20"
    end

    test "uses ns_ip as the apex IP unless :apex_ip is set", %{dir: dir} do
      assert {:ok, %{path: path}} =
               Bootstrap.create_authoritative_zone("ex.test",
                 dir: dir,
                 ns_ip: "192.0.2.30",
                 apex_ip: "192.0.2.99"
               )

      text = File.read!(path)
      assert text =~ "@   IN A    192.0.2.99"
    end

    test "is case- + trailing-dot-insensitive on apex", %{dir: dir} do
      {:ok, %{apex: a}} =
        Bootstrap.create_authoritative_zone("Ex.Test.", dir: dir, ns_ip: "1.2.3.4")

      assert a == "ex.test"
      assert "ex.test" in Storage.zones()
    end
  end

  describe "build_zone_text/2 (pure)" do
    test "produces parseable BIND-style text with the requested fields" do
      text =
        Bootstrap.build_zone_text("ex.test",
          ns_ip: "1.2.3.4",
          apex_ip: "5.6.7.8",
          contact: "ops.ex.test"
        )

      assert text =~ "$TTL 3600"
      assert text =~ "$ORIGIN ex.test."
      assert text =~ "ns1.ex.test. ops.ex.test."
      assert text =~ "ns1 IN A    1.2.3.4"
      assert text =~ "@   IN A    5.6.7.8"
    end
  end
end
