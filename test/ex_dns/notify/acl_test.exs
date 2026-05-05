defmodule ExDns.Notify.ACLTest do
  @moduledoc """
  Verifies the NOTIFY ACL: default-allow when no ACL configured,
  default-deny once one exists, IPv4 + IPv6 CIDR matching, and
  optional TSIG-key requirement.
  """

  use ExUnit.Case, async: false

  alias ExDns.Notify.ACL

  setup do
    previous = Application.get_env(:ex_dns, :notify_acls)

    on_exit(fn ->
      case previous do
        nil -> Application.delete_env(:ex_dns, :notify_acls)
        other -> Application.put_env(:ex_dns, :notify_acls, other)
      end
    end)

    :ok
  end

  test "no ACL configured → :allow" do
    Application.delete_env(:ex_dns, :notify_acls)
    assert :allow = ACL.check("example.test", {127, 0, 0, 1}, nil)
  end

  test "ACL configured but no allow_cidrs → :refuse" do
    Application.put_env(:ex_dns, :notify_acls, %{"example.test" => %{}})
    assert :refuse = ACL.check("example.test", {10, 0, 0, 1}, nil)
  end

  test "matching IPv4 CIDR → :allow" do
    Application.put_env(:ex_dns, :notify_acls, %{
      "example.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}
    })

    assert :allow = ACL.check("example.test", {10, 0, 0, 50}, nil)
    assert :refuse = ACL.check("example.test", {10, 0, 1, 50}, nil)
  end

  test "matching IPv6 CIDR → :allow" do
    Application.put_env(:ex_dns, :notify_acls, %{
      "example.test" => %{allow_cidrs: [{{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32}]}
    })

    assert :allow = ACL.check("example.test", {0x2001, 0xDB8, 0xFFFF, 1, 0, 0, 0, 1}, nil)
    assert :refuse = ACL.check("example.test", {0x2001, 0xDB7, 0xFFFF, 1, 0, 0, 0, 1}, nil)
  end

  test "require_tsig_key: matching key → :allow" do
    Application.put_env(:ex_dns, :notify_acls, %{
      "example.test" => %{
        allow_cidrs: [{{10, 0, 0, 0}, 8}],
        require_tsig_key: "primary"
      }
    })

    assert :allow = ACL.check("example.test", {10, 0, 0, 1}, "primary")
  end

  test "require_tsig_key: missing key → :refuse" do
    Application.put_env(:ex_dns, :notify_acls, %{
      "example.test" => %{
        allow_cidrs: [{{10, 0, 0, 0}, 8}],
        require_tsig_key: "primary"
      }
    })

    assert :refuse = ACL.check("example.test", {10, 0, 0, 1}, nil)
  end

  test "require_tsig_key: wrong key → :refuse" do
    Application.put_env(:ex_dns, :notify_acls, %{
      "example.test" => %{
        allow_cidrs: [{{10, 0, 0, 0}, 8}],
        require_tsig_key: "primary"
      }
    })

    assert :refuse = ACL.check("example.test", {10, 0, 0, 1}, "wrong-key")
  end

  test "ACLs are per-zone — unrelated zones untouched" do
    Application.put_env(:ex_dns, :notify_acls, %{
      "example.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}
    })

    assert :refuse = ACL.check("example.test", {99, 99, 99, 99}, nil)
    assert :allow = ACL.check("other.test", {99, 99, 99, 99}, nil)
  end

  test "telemetry decision events fire" do
    Application.put_env(:ex_dns, :notify_acls, %{
      "example.test" => %{allow_cidrs: [{{10, 0, 0, 0}, 24}]}
    })

    test_pid = self()

    :telemetry.attach(
      "notify-acl-test",
      [:ex_dns, :notify, :acl, :decision],
      fn _, _, metadata, _ -> send(test_pid, {:notify_acl, metadata}) end,
      %{}
    )

    on_exit(fn -> :telemetry.detach("notify-acl-test") end)

    ACL.check("example.test", {10, 0, 0, 1}, nil)
    assert_receive {:notify_acl, %{decision: :allow, zone: "example.test"}}

    ACL.check("example.test", {99, 99, 99, 99}, nil)
    assert_receive {:notify_acl, %{decision: :refuse}}
  end
end
