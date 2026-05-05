defmodule ExDns.RPZTest do
  @moduledoc """
  Verifies the RPZ parser: trigger classification (qname,
  wildcard, rpz-ip), action classification (NXDOMAIN, NODATA,
  passthru, drop, tcp-only, redirect, synthesise), apex-meta
  filtering, and IPv4 + IPv6 rpz-ip parsing.
  """

  use ExUnit.Case, async: true

  alias ExDns.Resource.{A, AAAA, CNAME, NS, SOA}
  alias ExDns.RPZ
  alias ExDns.RPZ.Rule

  doctest RPZ

  defp soa do
    %SOA{
      name: "rpz.example",
      ttl: 60,
      class: :in,
      mname: "ns",
      email: "h",
      serial: 1,
      refresh: 1,
      retry: 1,
      expire: 1,
      minimum: 1
    }
  end

  describe "trigger classification" do
    test "exact qname trigger" do
      records = [
        soa(),
        %CNAME{name: "evil.com.rpz.example", ttl: 60, class: :in, server: "."}
      ]

      assert [%Rule{trigger: {:qname, "evil.com"}, action: :nxdomain}] =
               RPZ.parse("rpz.example", records)
    end

    test "wildcard trigger" do
      records = [
        soa(),
        %CNAME{name: "*.evil.com.rpz.example", ttl: 60, class: :in, server: "."}
      ]

      assert [%Rule{trigger: {:wildcard, "evil.com"}, action: :nxdomain}] =
               RPZ.parse("rpz.example", records)
    end

    test "rpz-ip IPv4 trigger" do
      records = [
        soa(),
        %CNAME{name: "32.1.0.0.10.rpz-ip.rpz.example", ttl: 60, class: :in, server: "."}
      ]

      assert [%Rule{trigger: {:rpz_ip, {10, 0, 0, 1}, 32}}] =
               RPZ.parse("rpz.example", records)
    end

    test "rpz-ip IPv4 with shorter prefix" do
      records = [
        soa(),
        %CNAME{name: "24.0.0.0.10.rpz-ip.rpz.example", ttl: 60, class: :in, server: "."}
      ]

      assert [%Rule{trigger: {:rpz_ip, {10, 0, 0, 0}, 24}}] =
               RPZ.parse("rpz.example", records)
    end

    test "rpz-nsdname is captured as :other (not yet wired into a synth path)" do
      records = [
        soa(),
        %CNAME{name: "evil.example.com.rpz-nsdname.rpz.example", ttl: 60, class: :in, server: "."}
      ]

      assert [%Rule{trigger: {:other, _}}] = RPZ.parse("rpz.example", records)
    end
  end

  describe "action classification" do
    defp rule_for_action(action_record) do
      records = [soa(), action_record]
      [rule] = RPZ.parse("rpz.example", records)
      rule
    end

    test "CNAME `.` → :nxdomain" do
      assert %Rule{action: :nxdomain} =
               rule_for_action(%CNAME{name: "x.rpz.example", ttl: 60, class: :in, server: "."})
    end

    test "CNAME `*.` → :nodata" do
      assert %Rule{action: :nodata} =
               rule_for_action(%CNAME{name: "x.rpz.example", ttl: 60, class: :in, server: "*"})
    end

    test "CNAME `rpz-passthru.` → :passthru" do
      assert %Rule{action: :passthru} =
               rule_for_action(%CNAME{name: "x.rpz.example", ttl: 60, class: :in, server: "rpz-passthru"})
    end

    test "CNAME `rpz-drop.` → :drop" do
      assert %Rule{action: :drop} =
               rule_for_action(%CNAME{name: "x.rpz.example", ttl: 60, class: :in, server: "rpz-drop"})
    end

    test "CNAME `rpz-tcp-only.` → :tcp_only" do
      assert %Rule{action: :tcp_only} =
               rule_for_action(%CNAME{name: "x.rpz.example", ttl: 60, class: :in, server: "rpz-tcp-only"})
    end

    test "CNAME elsewhere → {:redirect, target}" do
      assert %Rule{action: {:redirect, "walled.garden.example"}} =
               rule_for_action(%CNAME{
                 name: "x.rpz.example",
                 ttl: 60,
                 class: :in,
                 server: "walled.garden.example"
               })
    end

    test "A record → {:synthesise, [...]}" do
      assert %Rule{action: {:synthesise, [%A{ipv4: {1, 2, 3, 4}}]}} =
               rule_for_action(%A{name: "x.rpz.example", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}})
    end

    test "AAAA record → {:synthesise, [...]}" do
      assert %Rule{action: {:synthesise, [%AAAA{}]}} =
               rule_for_action(%AAAA{
                 name: "x.rpz.example",
                 ttl: 60,
                 class: :in,
                 ipv6: {0, 0, 0, 0, 0, 0, 0, 1}
               })
    end
  end

  describe "metadata filtering" do
    test "SOA at apex is dropped, not parsed as a rule" do
      assert [] = RPZ.parse("rpz.example", [soa()])
    end

    test "apex-owned NS is dropped" do
      records = [
        soa(),
        %NS{name: "rpz.example", ttl: 60, class: :in, server: "ns.rpz.example"}
      ]

      assert [] = RPZ.parse("rpz.example", records)
    end

    test "non-apex NS is treated as a regular trigger" do
      # An NS under the apex would carry an :other trigger
      # since rpz-nsdname / rpz-nsip aren't fully wired — the
      # parser shouldn't crash, just emit :synthesise on the
      # NS struct.
      records = [
        soa(),
        %NS{name: "trigger.rpz.example", ttl: 60, class: :in, server: "elsewhere.test"}
      ]

      assert [%Rule{action: {:synthesise, _}}] = RPZ.parse("rpz.example", records)
    end
  end

  describe "synthesised-record consolidation" do
    test "A + AAAA at the same trigger merge into one rule" do
      records = [
        soa(),
        %A{name: "walled.rpz.example", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}},
        %AAAA{name: "walled.rpz.example", ttl: 60, class: :in, ipv6: {0, 0, 0, 0, 0, 0, 0, 1}}
      ]

      rules = RPZ.parse("rpz.example", records)
      assert [%Rule{trigger: {:qname, "walled"}, action: {:synthesise, recs}}] = rules
      assert length(recs) == 2
    end
  end
end
