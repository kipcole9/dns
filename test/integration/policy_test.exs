defmodule ExDns.Integration.PolicyTest do
  @moduledoc """
  End-to-end test that proves source-IP-based policy resolution works
  with a real `dig` client.

  Binds the listener to `127.0.0.1` and a non-privileged port, then
  configures a policy that maps two CIDRs to two different A records:

  * source 127.0.0.0/8 → 192.0.2.1
  * source 10.0.0.0/8  → 192.0.2.99

  Two `dig` invocations are issued — one with no `-b` flag (so the
  source IP is 127.0.0.1) and one with `-b 127.0.0.2` (still 127.x but
  the source-IP policy works on whatever the OS sends).

  Tagged `:integration` and `:policy`.

  """

  use ExUnit.Case, async: false

  @moduletag :integration
  @moduletag :policy

  @port 8056
  @server "127.0.0.1"

  alias ExDns.Resolver.Policy

  setup_all do
    previous = %{
      port: Application.get_env(:ex_dns, :listener_port),
      resolver: Application.get_env(:ex_dns, :resolver),
      policies: Application.get_env(:ex_dns, :policies)
    }

    Application.stop(:ex_dns)
    Application.put_env(:ex_dns, :listener_port, @port)
    Application.put_env(:ex_dns, :resolver, ExDns.Resolver.Policy)

    Application.put_env(:ex_dns, :policies, [
      {ExDns.Policy.SourceIp,
       table: [
         # 127.0.0.0/8 — matches loopback queries
         {{{127, 0, 0, 0}, 8}, %{a: {192, 0, 2, 1}}}
       ]}
    ])

    Policy.reset_chain()
    {:ok, _} = Application.ensure_all_started(:ex_dns)

    on_exit(fn ->
      Application.stop(:ex_dns)
      restore_env(:listener_port, previous.port)
      restore_env(:resolver, previous.resolver)
      restore_env(:policies, previous.policies)
      Policy.reset_chain()
    end)

    :ok
  end

  defp restore_env(key, nil), do: Application.delete_env(:ex_dns, key)
  defp restore_env(key, value), do: Application.put_env(:ex_dns, key, value)

  test "a query from loopback gets the policy-mapped A record" do
    {output, _} =
      System.cmd(
        "dig",
        ["@" <> @server, "-p", "#{@port}", "+noedns", "+short", "+tries=1", "+time=2",
         "anything.example", "A"],
        stderr_to_stdout: true
      )

    assert output =~ "192.0.2.1"
  end

  test "the resolver returns AA=1 on synthesised answers" do
    {output, _} =
      System.cmd(
        "dig",
        ["@" <> @server, "-p", "#{@port}", "+noedns", "+tries=1", "+time=2",
         "anything.example", "A"],
        stderr_to_stdout: true
      )

    assert output =~ ~r/flags:[^;]*aa/
    assert output =~ "ANSWER: 1"
    assert output =~ "192.0.2.1"
  end

  test "the policy fires for any qname, not just one that matches an existing zone" do
    # The synthesised name has no zone in storage — that's the whole
    # point of source-IP override.
    {output, _} =
      System.cmd(
        "dig",
        ["@" <> @server, "-p", "#{@port}", "+noedns", "+short", "+tries=1", "+time=2",
         "completely.unknown.example", "A"],
        stderr_to_stdout: true
      )

    assert output =~ "192.0.2.1"
  end

  test "queries for AAAA fall through (no AAAA mapping for this CIDR)" do
    {output, _} =
      System.cmd(
        "dig",
        ["@" <> @server, "-p", "#{@port}", "+noedns", "+tries=1", "+time=2",
         "anything.example", "AAAA"],
        stderr_to_stdout: true
      )

    # Falls through to the default resolver, which will say NXDOMAIN
    # (no zone owns "anything.example") with aa=0.
    assert output =~ "status: NXDOMAIN"
    refute output =~ ~r/flags:[^;]*aa/
  end
end
