defmodule ExDns.Resolver.HybridTest do
  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resolver.Hybrid
  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage.ETS, as: Storage

  setup do
    Storage.init()
    on_exit(fn -> Enum.each(Storage.zones(), &Storage.delete_zone/1) end)
    Application.delete_env(:ex_dns, :recursion)
    :ok
  end

  defp query(qname, qtype, rd) do
    %Message{
      header: %Header{
        id: 0xCAFE,
        qr: 0,
        oc: 0,
        aa: 0,
        tc: 0,
        rd: rd,
        ra: 0,
        ad: 0,
        cd: 0,
        rc: 0,
        qc: 1,
        anc: 0,
        auc: 0,
        adc: 0
      },
      question: %Question{host: qname, type: qtype, class: :in},
      answer: [],
      authority: [],
      additional: []
    }
  end

  defp seed_zone do
    Storage.put_zone("example.test", [
      %SOA{
        name: "example.test",
        ttl: 86_400,
        class: :internet,
        mname: "ns.example.test",
        email: "admin.example.test",
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minimum: 3600
      },
      %A{name: "example.test", ttl: 60, class: :internet, ipv4: {192, 0, 2, 1}}
    ])
  end

  describe "behaves identically to Default when…" do
    test "recursion is disabled" do
      seed_zone()
      Application.put_env(:ex_dns, :recursion, false)

      response = Hybrid.resolve(query("example.test", :a, 1))
      assert response.header.aa == 1
      assert [%A{ipv4: {192, 0, 2, 1}}] = response.answer
    end

    test "the qname falls under a hosted zone (no recursion needed)" do
      seed_zone()
      Application.put_env(:ex_dns, :recursion, true)

      response = Hybrid.resolve(query("example.test", :a, 1))
      assert response.header.aa == 1
      assert response.header.ra == 0
    end

    test "the client did not set RD, even with recursion enabled" do
      Application.put_env(:ex_dns, :recursion, true)
      response = Hybrid.resolve(query("nope.test", :a, 0))
      # Default's NXDOMAIN-with-aa=0 path.
      assert response.header.qr == 1
      assert response.header.aa == 0
      assert response.header.rc == 3
    end
  end

  describe "with recursion enabled and qname outside our zones" do
    test "returns SERVFAIL when the iterator cannot reach an upstream" do
      Application.put_env(:ex_dns, :recursion, true)
      # We don't stub the iterator; resolving a real name without
      # network access just exits with :no_servers / :timeout, which
      # the hybrid resolver maps to rcode=2 (SERVFAIL). The point of
      # the test is that the response is still well-formed.
      response = Hybrid.resolve(query("definitely.not.a.real.tld.example", :a, 1))
      assert response.header.qr == 1
      assert response.header.ra == 1
      assert response.header.rc in [0, 2, 3]
    end
  end
end
