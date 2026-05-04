defmodule ExDns.Resolver.IxfrTest do
  @moduledoc """
  Verifies the resolver answers IXFR queries (RFC 1995) using the
  zone journal: serves a differences-sequence when the journal can
  satisfy the request, returns a single SOA when the client is
  already current, and falls back to AXFR when no journal entry
  applies.
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resolver.Default
  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage
  alias ExDns.Zone.Journal

  setup do
    Storage.init()
    Journal.clear()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)
    on_exit(fn -> Enum.each(Storage.zones(), &Storage.delete_zone/1) end)
    :ok
  end

  defp soa(serial) do
    %SOA{
      name: "example.test",
      ttl: 60,
      class: :in,
      mname: "ns",
      email: "h",
      serial: serial,
      refresh: 1,
      retry: 1,
      expire: 1,
      minimum: 1
    }
  end

  defp a(name, ip) do
    %A{name: name, ttl: 60, class: :in, ipv4: ip}
  end

  defp ixfr_query(qname, client_serial) do
    %Message{
      header: %Header{
        id: 0xABCD,
        qr: 0,
        oc: 0,
        aa: 0,
        tc: 0,
        rd: 0,
        ra: 0,
        ad: 0,
        cd: 0,
        rc: 0,
        qc: 1,
        anc: 0,
        auc: 1,
        adc: 0
      },
      question: %Question{host: qname, type: :ixfr, class: :in},
      answer: [],
      authority: [soa(client_serial)],
      additional: []
    }
  end

  test "returns a single SOA when the client is already current" do
    Storage.put_zone("example.test", [soa(7), a("host.example.test", {1, 1, 1, 1})])

    response = Default.resolve(ixfr_query("example.test", 7))

    assert response.header.rc == 0
    assert response.header.aa == 1
    assert [%SOA{serial: 7}] = response.answer
  end

  test "returns a differences-sequence when the journal can satisfy it" do
    Storage.put_zone("example.test", [soa(1), a("a.example.test", {1, 1, 1, 1})])

    Storage.put_zone("example.test", [
      soa(2),
      a("a.example.test", {1, 1, 1, 1}),
      a("b.example.test", {2, 2, 2, 2})
    ])

    response = Default.resolve(ixfr_query("example.test", 1))

    # RFC 1995 §4: SOA(new), [SOA(old), removed..., SOA(new), added...]+, SOA(new)
    # For a single 1→2 delta with one added record:
    #   SOA(2), SOA(1), SOA(2), A(b.example.test), SOA(2)
    assert response.header.rc == 0
    assert response.header.aa == 1

    serials = for %SOA{serial: s} <- response.answer, do: s
    # Boundary SOAs both serial 2.
    assert hd(serials) == 2
    assert List.last(serials) == 2
    # Mid-chain mentions serial 1 (the old serial) at least once.
    assert 1 in serials
    # The added record appears in the answer.
    assert Enum.any?(response.answer, &match?(%A{name: "b.example.test"}, &1))
  end

  test "falls back to AXFR when journal cannot satisfy the request" do
    Storage.put_zone("example.test", [soa(10), a("host.example.test", {1, 1, 1, 1})])

    # Client claims to have serial 5; we have no journal entries
    # going that far back. Per RFC 1995 §2 we fall back to AXFR.
    response = Default.resolve(ixfr_query("example.test", 5))

    assert response.header.rc == 0
    assert response.header.aa == 1
    # AXFR opens and closes with the SOA.
    assert [%SOA{serial: 10} | _] = response.answer
    assert match?(%SOA{serial: 10}, List.last(response.answer))
  end

  test "falls back to AXFR when no client SOA is provided in authority" do
    Storage.put_zone("example.test", [soa(3), a("host.example.test", {1, 1, 1, 1})])

    query = %{ixfr_query("example.test", 3) | authority: []}
    response = Default.resolve(query)

    assert response.header.rc == 0
    # AXFR fallback: SOA + records + SOA.
    assert [%SOA{serial: 3} | _] = response.answer
    assert match?(%SOA{}, List.last(response.answer))
  end

  test "REFUSED for an unknown zone" do
    response = Default.resolve(ixfr_query("nonexistent.test", 1))
    assert response.header.rc == 5
  end

  test "multi-step chain: client at serial 1, current is 3, journal has 1→2 and 2→3" do
    Storage.put_zone("example.test", [soa(1)])
    Storage.put_zone("example.test", [soa(2), a("x.example.test", {1, 1, 1, 1})])

    Storage.put_zone("example.test", [
      soa(3),
      a("x.example.test", {1, 1, 1, 1}),
      a("y.example.test", {2, 2, 2, 2})
    ])

    response = Default.resolve(ixfr_query("example.test", 1))

    serials = for %SOA{serial: s} <- response.answer, do: s
    # Chain has two delta-pairs. Boundary SOAs are serial 3.
    assert hd(serials) == 3
    assert List.last(serials) == 3
    # Both intermediate serials should appear.
    assert 1 in serials
    assert 2 in serials
    # Both added records should appear.
    assert Enum.any?(response.answer, &match?(%A{name: "x.example.test"}, &1))
    assert Enum.any?(response.answer, &match?(%A{name: "y.example.test"}, &1))
  end
end
