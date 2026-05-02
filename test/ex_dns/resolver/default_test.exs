defmodule ExDns.Resolver.DefaultTest do
  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Resolver.Default
  alias ExDns.Resource.{A, CNAME, NS, SOA}
  alias ExDns.Storage.ETS, as: Storage

  setup do
    Storage.init()
    on_exit(fn -> Enum.each(Storage.zones(), &Storage.delete_zone/1) end)
    :ok
  end

  defp seed_zone do
    Storage.put_zone("example.com", [
      %SOA{
        name: "example.com",
        ttl: 86_400,
        class: :internet,
        mname: "ns.example.com",
        email: "hostmaster.example.com",
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minimum: 3600
      },
      %NS{name: "example.com", ttl: 86_400, class: :internet, server: "ns.example.com"},
      %A{name: "example.com", ttl: 60, class: :internet, ipv4: {192, 0, 2, 1}},
      %A{name: "ns.example.com", ttl: 60, class: :internet, ipv4: {192, 0, 2, 53}}
    ])
  end

  defp query(qname, qtype) do
    %Message{
      header: %Header{
        id: 0xCAFE,
        qr: 0,
        oc: 0,
        aa: 0,
        tc: 0,
        rd: 1,
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

  describe "resolve/1 — exact match" do
    test "returns an authoritative A answer" do
      seed_zone()
      response = Default.resolve(query("example.com", :a))

      assert response.header.qr == 1
      assert response.header.aa == 1
      assert response.header.rc == 0
      assert response.header.anc == 1
      assert [%A{ipv4: {192, 0, 2, 1}, class: :in}] = response.answer
      assert response.question == query("example.com", :a).question
    end

    test "returns NODATA (NOERROR + 0 answers) when name exists but type does not" do
      seed_zone()
      response = Default.resolve(query("example.com", :aaaa))

      assert response.header.qr == 1
      assert response.header.aa == 1
      assert response.header.rc == 0
      assert response.header.anc == 0
      assert response.answer == []
    end
  end

  describe "resolve/1 — NXDOMAIN" do
    test "returns NXDOMAIN with AA=1 inside a known zone" do
      seed_zone()
      response = Default.resolve(query("missing.example.com", :a))

      assert response.header.qr == 1
      assert response.header.aa == 1
      assert response.header.rc == 3
      assert response.header.anc == 0
    end

    test "returns NXDOMAIN with AA=0 outside any known zone" do
      seed_zone()
      response = Default.resolve(query("nope.test", :a))

      assert response.header.qr == 1
      assert response.header.aa == 0
      assert response.header.rc == 3
    end
  end

  describe "resolve/1 — round-trip through wire format" do
    test "encoded response can be decoded back into a query+answer pair" do
      seed_zone()
      query_message = query("example.com", :a)
      response = Default.resolve(query_message)

      bytes = Message.encode(response)
      assert {:ok, decoded} = Message.decode(bytes)

      assert decoded.header.qr == 1
      assert decoded.header.aa == 1
      assert decoded.header.id == query_message.header.id
      assert [%A{ipv4: {192, 0, 2, 1}}] = decoded.answer
    end
  end

  describe "resolve/1 — CNAME chasing within zone" do
    setup do
      Storage.put_zone("example.com", [
        %SOA{
          name: "example.com",
          ttl: 86_400,
          class: :internet,
          mname: "ns.example.com",
          email: "hostmaster.example.com",
          serial: 1,
          refresh: 7200,
          retry: 3600,
          expire: 1_209_600,
          minimum: 3600
        },
        %A{name: "example.com", ttl: 60, class: :internet, ipv4: {192, 0, 2, 1}},
        %A{name: "host.example.com", ttl: 60, class: :internet, ipv4: {192, 0, 2, 9}},
        %CNAME{name: "alias.example.com", ttl: 300, class: :internet, server: "host.example.com"},
        %CNAME{name: "alias2.example.com", ttl: 300, class: :internet, server: "alias.example.com"},
        %CNAME{name: "loose.example.com", ttl: 300, class: :internet, server: "missing.example.com"}
      ])

      :ok
    end

    test "follows a single CNAME and returns both records" do
      response = Default.resolve(query("alias.example.com", :a))
      assert response.header.rc == 0
      assert response.header.aa == 1
      assert length(response.answer) == 2
      [first, second] = response.answer
      assert %CNAME{server: "host.example.com"} = first
      assert %A{ipv4: {192, 0, 2, 9}} = second
    end

    test "follows a chained CNAME (alias2 → alias → host)" do
      response = Default.resolve(query("alias2.example.com", :a))
      assert response.header.rc == 0
      assert length(response.answer) == 3
      assert [%CNAME{}, %CNAME{}, %A{ipv4: {192, 0, 2, 9}}] = response.answer
    end

    test "returns the CNAME itself when the chain ends in a missing target" do
      response = Default.resolve(query("loose.example.com", :a))
      # NOERROR with the CNAME in the answer; SOA in authority for negative caching.
      assert response.header.rc == 0
      assert [%CNAME{server: "missing.example.com"}] = response.answer
      assert [%SOA{}] = response.authority
    end

    test "does NOT chase when the query type is itself CNAME" do
      response = Default.resolve(query("alias.example.com", :cname))
      assert response.header.rc == 0
      assert [%CNAME{server: "host.example.com"}] = response.answer
    end
  end

  describe "resolve/1 — NS delegation + glue" do
    setup do
      Storage.put_zone("parent.test", [
        %SOA{
          name: "parent.test",
          ttl: 86_400,
          class: :internet,
          mname: "ns.parent.test",
          email: "admin.parent.test",
          serial: 1,
          refresh: 7200,
          retry: 3600,
          expire: 1_209_600,
          minimum: 3600
        },
        %NS{name: "parent.test", ttl: 86_400, class: :internet, server: "ns.parent.test"},
        %A{name: "ns.parent.test", ttl: 86_400, class: :internet, ipv4: {192, 0, 2, 53}},
        # Delegation to a child zone we do NOT serve, with in-bailiwick
        # glue so the resolver can locate the child name servers.
        %NS{name: "sub.parent.test", ttl: 86_400, class: :internet, server: "ns1.sub.parent.test"},
        %NS{name: "sub.parent.test", ttl: 86_400, class: :internet, server: "ns2.sub.parent.test"},
        %A{name: "ns1.sub.parent.test", ttl: 86_400, class: :internet, ipv4: {198, 51, 100, 1}},
        %A{name: "ns2.sub.parent.test", ttl: 86_400, class: :internet, ipv4: {198, 51, 100, 2}}
      ])

      :ok
    end

    test "queries below a delegation cut return a referral, not an authoritative answer" do
      response = Default.resolve(query("host.sub.parent.test", :a))

      # Referral: AA cleared, NOERROR, empty answer, NS in authority.
      assert response.header.qr == 1
      assert response.header.aa == 0
      assert response.header.rc == 0
      assert response.answer == []
      assert length(response.authority) == 2
      Enum.each(response.authority, fn record -> assert %ExDns.Resource.NS{} = record end)
    end

    test "referral includes glue A records in additional" do
      response = Default.resolve(query("host.sub.parent.test", :a))

      additional_no_opt =
        Enum.reject(response.additional, &match?(%ExDns.Resource.OPT{}, &1))

      assert length(additional_no_opt) == 2
      ips = Enum.map(additional_no_opt, & &1.ipv4)
      assert {198, 51, 100, 1} in ips
      assert {198, 51, 100, 2} in ips
    end

    test "queries AT the delegation point for NS still go through (parent owns those NS)" do
      response = Default.resolve(query("sub.parent.test", :ns))
      # We expect the NS records in the answer (with AA), not as a referral.
      assert response.header.aa == 1
      assert length(response.answer) == 2
    end

    test "queries above the cut still resolve authoritatively" do
      response = Default.resolve(query("parent.test", :a))
      # No A at apex in this zone — NODATA with AA=1.
      assert response.header.aa == 1
      assert response.header.rc == 0
      assert response.answer == []
    end
  end

  describe "resolve/1 — AXFR" do
    setup do
      Storage.put_zone("xfer.test", [
        %SOA{
          name: "xfer.test",
          ttl: 86_400,
          class: :internet,
          mname: "ns.xfer.test",
          email: "admin.xfer.test",
          serial: 1,
          refresh: 7200,
          retry: 3600,
          expire: 1_209_600,
          minimum: 3600
        },
        %NS{name: "xfer.test", ttl: 86_400, class: :internet, server: "ns.xfer.test"},
        %A{name: "xfer.test", ttl: 60, class: :internet, ipv4: {192, 0, 2, 1}},
        %A{name: "ns.xfer.test", ttl: 60, class: :internet, ipv4: {192, 0, 2, 53}}
      ])

      :ok
    end

    test "AXFR for the apex returns SOA … records … SOA" do
      response = Default.resolve(query("xfer.test", :axfr))
      assert response.header.rc == 0
      assert response.header.aa == 1
      assert [first | _] = response.answer
      assert %SOA{} = first
      assert %SOA{} = List.last(response.answer)
      # 1 SOA + 1 NS + 2 As + final SOA = 5 records
      assert length(response.answer) == 5
    end

    test "AXFR for a non-apex name returns REFUSED" do
      response = Default.resolve(query("ns.xfer.test", :axfr))
      assert response.header.rc == 5
    end

    test "AXFR for an unknown zone returns REFUSED" do
      response = Default.resolve(query("nope.test", :axfr))
      assert response.header.rc == 5
    end

    test "IXFR falls back to a full AXFR" do
      response = Default.resolve(query("xfer.test", :ixfr))
      assert response.header.rc == 0
      # Same shape as the AXFR test above.
      assert length(response.answer) == 5
      assert %SOA{} = hd(response.answer)
      assert %SOA{} = List.last(response.answer)
    end
  end

  describe "resolve/1 — wildcards (RFC 4592)" do
    setup do
      Storage.put_zone("wild.test", [
        %SOA{
          name: "wild.test",
          ttl: 86_400,
          class: :internet,
          mname: "ns.wild.test",
          email: "admin.wild.test",
          serial: 1,
          refresh: 7200,
          retry: 3600,
          expire: 1_209_600,
          minimum: 3600
        },
        %A{name: "wild.test", ttl: 60, class: :internet, ipv4: {192, 0, 2, 1}},
        %A{name: "*.wild.test", ttl: 60, class: :internet, ipv4: {198, 51, 100, 99}},
        %A{name: "explicit.wild.test", ttl: 60, class: :internet, ipv4: {192, 0, 2, 5}}
      ])

      :ok
    end

    test "wildcard synthesises an answer for an unmatched name" do
      response = Default.resolve(query("anything.wild.test", :a))
      assert response.header.rc == 0
      assert response.header.aa == 1
      assert [%A{name: "anything.wild.test", ipv4: {198, 51, 100, 99}}] = response.answer
    end

    test "explicit name shadows the wildcard" do
      response = Default.resolve(query("explicit.wild.test", :a))
      assert [%A{name: "explicit.wild.test", ipv4: {192, 0, 2, 5}}] = response.answer
    end

    test "wildcard does not apply when the queried type does not exist on the wildcard" do
      response = Default.resolve(query("anything.wild.test", :aaaa))
      # NODATA — wildcard exists for A but the query was AAAA
      assert response.header.rc == 0
      assert response.answer == []
    end
  end

  describe "resolve/1 — ANY queries" do
    setup do
      Storage.put_zone("any.test", [
        %SOA{
          name: "any.test",
          ttl: 86_400,
          class: :internet,
          mname: "ns.any.test",
          email: "admin.any.test",
          serial: 1,
          refresh: 7200,
          retry: 3600,
          expire: 1_209_600,
          minimum: 3600
        },
        %A{name: "host.any.test", ttl: 60, class: :internet, ipv4: {192, 0, 2, 1}},
        %A{name: "host.any.test", ttl: 60, class: :internet, ipv4: {192, 0, 2, 2}},
        %ExDns.Resource.AAAA{
          name: "host.any.test",
          ttl: 60,
          class: :internet,
          ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}
        },
        %ExDns.Resource.MX{
          name: "host.any.test",
          ttl: 60,
          class: :internet,
          priority: 10,
          server: "mail.any.test"
        }
      ])

      :ok
    end

    test "returns every RRset at the name" do
      response = Default.resolve(query("host.any.test", :any))

      assert response.header.rc == 0
      assert response.header.aa == 1
      types = Enum.map(response.answer, & &1.__struct__)
      assert ExDns.Resource.A in types
      assert ExDns.Resource.AAAA in types
      assert ExDns.Resource.MX in types

      a_records = Enum.filter(response.answer, &match?(%ExDns.Resource.A{}, &1))
      assert length(a_records) == 2
    end

    test "ANY for an unknown name returns NXDOMAIN with the apex SOA in authority" do
      response = Default.resolve(query("missing.any.test", :any))
      assert response.header.rc == 3
      assert response.header.aa == 1
      assert [%SOA{}] = response.authority
    end
  end

  describe "resolve/1 — NOTIFY (opcode 4)" do
    setup do
      Storage.put_zone("notify.test", [
        %SOA{
          name: "notify.test",
          ttl: 86_400,
          class: :internet,
          mname: "ns.notify.test",
          email: "admin.notify.test",
          serial: 1,
          refresh: 7200,
          retry: 3600,
          expire: 1_209_600,
          minimum: 3600
        }
      ])

      :ok
    end

    test "acknowledges with NOERROR + AA=1 when we own the zone" do
      query = query("notify.test", :soa)
      header = %Message.Header{query.header | oc: 4}
      notify = %Message{query | header: header}
      response = Default.resolve(notify)

      assert response.header.qr == 1
      assert response.header.oc == 4
      assert response.header.rc == 0
      assert response.header.aa == 1
    end

    test "acknowledges with NOERROR + AA=0 when we don't own the zone" do
      query = query("foreign.test", :soa)
      header = %Message.Header{query.header | oc: 4}
      notify = %Message{query | header: header}
      response = Default.resolve(notify)

      assert response.header.qr == 1
      assert response.header.rc == 0
      assert response.header.aa == 0
    end
  end

  describe "resolve/1 — unsupported opcodes" do
    test "returns NOTIMP for inverse queries" do
      response =
        %Message{query("any.example", :a) | header: %Header{query("any.example", :a).header | oc: 1}}
        |> Default.resolve()

      assert response.header.rc == 4
      assert response.header.qr == 1
    end
  end
end
