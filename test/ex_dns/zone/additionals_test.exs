defmodule ExDns.Zone.AdditionalsTest do
  @moduledoc """
  Verifies auto-derivation of A/AAAA glue from NS / MX / SRV
  targets present in answer or authority sections.
  """

  use ExUnit.Case, async: false

  alias ExDns.Resource.{A, AAAA, MX, NS, SOA, SRV}
  alias ExDns.Storage
  alias ExDns.Zone.Additionals

  doctest Additionals

  setup do
    Storage.init()

    Storage.put_zone("glue.example", [
      %SOA{
        name: "glue.example",
        ttl: 60,
        class: :in,
        mname: "ns1.glue.example",
        email: "h",
        serial: 1,
        refresh: 60,
        retry: 60,
        expire: 60,
        minimum: 60
      },
      %A{name: "ns1.glue.example", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}},
      %AAAA{name: "ns1.glue.example", ttl: 60, class: :in, ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}},
      %A{name: "mail.glue.example", ttl: 60, class: :in, ipv4: {192, 0, 2, 25}},
      %A{name: "sip.glue.example", ttl: 60, class: :in, ipv4: {192, 0, 2, 60}}
    ])

    on_exit(fn -> Storage.delete_zone("glue.example") end)

    :ok
  end

  describe "derive/2" do
    test "NS target → A and AAAA glue" do
      ns = %NS{name: "glue.example", ttl: 60, class: :in, server: "ns1.glue.example"}

      result = Additionals.derive([ns])

      assert Enum.any?(result, &match?(%A{ipv4: {192, 0, 2, 1}}, &1))
      assert Enum.any?(result, &match?(%AAAA{}, &1))
    end

    test "MX target → A glue" do
      mx = %MX{name: "glue.example", ttl: 60, class: :in, priority: 10, server: "mail.glue.example"}

      result = Additionals.derive([mx])

      assert Enum.any?(result, &match?(%A{ipv4: {192, 0, 2, 25}}, &1))
    end

    test "SRV target → A glue" do
      srv = %SRV{
        name: "_sip._udp.glue.example",
        ttl: 60,
        class: :in,
        priority: 10,
        weight: 5,
        port: 5060,
        target: "sip.glue.example"
      }

      result = Additionals.derive([srv])

      assert Enum.any?(result, &match?(%A{ipv4: {192, 0, 2, 60}}, &1))
    end

    test "out-of-bailiwick targets produce no additional" do
      mx = %MX{
        name: "glue.example",
        ttl: 60,
        class: :in,
        priority: 10,
        server: "mail.elsewhere.test"
      }

      assert [] = Additionals.derive([mx])
    end

    test "records already in the answer set are not duplicated" do
      ns = %NS{name: "glue.example", ttl: 60, class: :in, server: "ns1.glue.example"}
      a = %A{name: "ns1.glue.example", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}

      result = Additionals.derive([ns, a], [a])
      refute Enum.any?(result, &match?(%A{ipv4: {192, 0, 2, 1}}, &1))
    end

    test "records already in the supplied additional set are not duplicated" do
      ns = %NS{name: "glue.example", ttl: 60, class: :in, server: "ns1.glue.example"}
      already = %A{name: "ns1.glue.example", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}

      result = Additionals.derive([ns], [already])
      refute Enum.any?(result, &match?(%A{ipv4: {192, 0, 2, 1}}, &1))
      # AAAA glue is still present because it wasn't in `already`.
      assert Enum.any?(result, &match?(%AAAA{}, &1))
    end

    test "case-insensitive target matching" do
      mx = %MX{
        name: "glue.example",
        ttl: 60,
        class: :in,
        priority: 10,
        server: "MAIL.GLUE.EXAMPLE"
      }

      result = Additionals.derive([mx])
      assert Enum.any?(result, &match?(%A{ipv4: {192, 0, 2, 25}}, &1))
    end

    test "no-op for answer sections without NS/MX/SRV" do
      a = %A{name: "host.glue.example", ttl: 60, class: :in, ipv4: {1, 2, 3, 4}}
      assert [] = Additionals.derive([a])
    end

    test "duplicate targets across multiple records collapse to one lookup" do
      mx1 = %MX{
        name: "glue.example",
        ttl: 60,
        class: :in,
        priority: 10,
        server: "mail.glue.example"
      }

      mx2 = %MX{
        name: "glue.example",
        ttl: 60,
        class: :in,
        priority: 20,
        server: "mail.glue.example"
      }

      result = Additionals.derive([mx1, mx2])
      a_records = Enum.filter(result, &match?(%A{}, &1))
      assert length(a_records) == 1
    end
  end
end
