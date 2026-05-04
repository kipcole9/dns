defmodule ExDns.Transfer.ACLTest do
  @moduledoc """
  Verifies the per-zone transfer ACL: default-allow when no ACL is
  configured, default-deny once an ACL exists, CIDR matching for
  IPv4 and IPv6, and the optional TSIG-key requirement.
  """

  use ExUnit.Case, async: false

  alias ExDns.Transfer.ACL

  doctest ACL

  setup do
    previous = Application.get_env(:ex_dns, :transfer_acls)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :transfer_acls)
        other -> Application.put_env(:ex_dns, :transfer_acls, other)
      end
    end)

    :ok
  end

  test "no ACL configured → :allow" do
    Application.delete_env(:ex_dns, :transfer_acls)
    assert :allow = ACL.check("example.test", {127, 0, 0, 1}, nil)
  end

  test "ACL configured but no allow_cidrs → :refuse" do
    Application.put_env(:ex_dns, :transfer_acls, %{"example.test" => %{}})
    assert :refuse = ACL.check("example.test", {10, 0, 0, 1}, nil)
  end

  test "matching IPv4 CIDR → :allow" do
    Application.put_env(:ex_dns, :transfer_acls, %{
      "example.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}
    })

    assert :allow = ACL.check("example.test", {10, 0, 0, 50}, nil)
    assert :refuse = ACL.check("example.test", {10, 0, 1, 50}, nil)
  end

  test "matching /32 (single host) IPv4 CIDR" do
    Application.put_env(:ex_dns, :transfer_acls, %{
      "example.test" => %{allow_cidrs: [{{192, 0, 2, 5}, 32}]}
    })

    assert :allow = ACL.check("example.test", {192, 0, 2, 5}, nil)
    assert :refuse = ACL.check("example.test", {192, 0, 2, 6}, nil)
  end

  test "matching IPv6 CIDR" do
    Application.put_env(:ex_dns, :transfer_acls, %{
      "example.test" => %{allow_cidrs: [{{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32}]}
    })

    assert :allow = ACL.check("example.test", {0x2001, 0xDB8, 0xFFFF, 1, 0, 0, 0, 1}, nil)
    assert :refuse = ACL.check("example.test", {0x2001, 0xDB7, 0xFFFF, 1, 0, 0, 0, 1}, nil)
  end

  test "require_tsig_key: matching key → :allow" do
    Application.put_env(:ex_dns, :transfer_acls, %{
      "example.test" => %{
        allow_cidrs: [{{10, 0, 0, 0}, 8}],
        require_tsig_key: "secondary"
      }
    })

    assert :allow = ACL.check("example.test", {10, 0, 0, 1}, "secondary")
  end

  test "require_tsig_key: missing key → :refuse" do
    Application.put_env(:ex_dns, :transfer_acls, %{
      "example.test" => %{
        allow_cidrs: [{{10, 0, 0, 0}, 8}],
        require_tsig_key: "secondary"
      }
    })

    assert :refuse = ACL.check("example.test", {10, 0, 0, 1}, nil)
  end

  test "require_tsig_key: wrong key → :refuse" do
    Application.put_env(:ex_dns, :transfer_acls, %{
      "example.test" => %{
        allow_cidrs: [{{10, 0, 0, 0}, 8}],
        require_tsig_key: "secondary"
      }
    })

    assert :refuse = ACL.check("example.test", {10, 0, 0, 1}, "wrong-key")
  end

  test "ACLs are per-zone — unrelated zones untouched" do
    Application.put_env(:ex_dns, :transfer_acls, %{
      "example.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}
    })

    assert :refuse = ACL.check("example.test", {99, 99, 99, 99}, nil)
    assert :allow = ACL.check("other.test", {99, 99, 99, 99}, nil)
  end

  test "telemetry decision events fire" do
    Application.put_env(:ex_dns, :transfer_acls, %{
      "example.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}
    })

    test_pid = self()

    :telemetry.attach(
      "acl-test",
      [:ex_dns, :transfer, :acl, :decision],
      fn _, _, metadata, _ -> send(test_pid, {:acl, metadata}) end,
      %{}
    )

    on_exit(fn -> :telemetry.detach("acl-test") end)

    ACL.check("example.test", {10, 0, 0, 1}, nil)
    assert_receive {:acl, %{decision: :allow, zone: "example.test"}}

    ACL.check("example.test", {99, 99, 99, 99}, nil)
    assert_receive {:acl, %{decision: :refuse}}
  end
end
