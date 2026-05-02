defmodule ExDns.Message.RoundTripTest do
  use ExUnit.Case, async: true

  alias ExDns.Message

  defp blank_header(opts) do
    defaults = [
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
      qc: 0,
      anc: 0,
      auc: 0,
      adc: 0
    ]

    struct!(Message.Header, Keyword.merge(defaults, opts))
  end

  describe "encode/1 → decode/1" do
    test "round-trips a query (header + question, no records)" do
      message = %Message{
        header: blank_header(qc: 1),
        question: %Message.Question{host: "example.com", type: :a, class: :in},
        answer: [],
        authority: [],
        additional: []
      }

      bytes = Message.encode(message)
      assert {:ok, decoded} = Message.decode(bytes)

      assert decoded.header.id == message.header.id
      assert decoded.question == message.question
      assert decoded.answer == []
      assert decoded.authority == []
      assert decoded.additional == []
    end

    test "round-trips a response with one A answer" do
      answer = %ExDns.Resource.A{
        name: "example.com",
        ttl: 300,
        class: :in,
        ipv4: {192, 0, 2, 1}
      }

      message = %Message{
        header: blank_header(qr: 1, aa: 1, qc: 1, anc: 1),
        question: %Message.Question{host: "example.com", type: :a, class: :in},
        answer: [answer],
        authority: [],
        additional: []
      }

      bytes = Message.encode(message)
      assert {:ok, decoded} = Message.decode(bytes)

      assert decoded.header.qr == 1
      assert decoded.header.aa == 1
      assert decoded.header.anc == 1
      assert [decoded_answer] = decoded.answer
      assert decoded_answer == answer
    end

    test "round-trips multi-section: 2 answers + 1 authority + 1 additional" do
      answers = [
        %ExDns.Resource.A{name: "example.com", ttl: 300, class: :in, ipv4: {192, 0, 2, 1}},
        %ExDns.Resource.A{name: "example.com", ttl: 300, class: :in, ipv4: {192, 0, 2, 2}}
      ]

      authorities = [
        %ExDns.Resource.NS{name: "example.com", ttl: 86_400, class: :in, server: "ns1.example.com"}
      ]

      additionals = [
        %ExDns.Resource.A{name: "ns1.example.com", ttl: 86_400, class: :in, ipv4: {192, 0, 2, 53}}
      ]

      message = %Message{
        header: blank_header(qr: 1, aa: 1, qc: 1, anc: 2, auc: 1, adc: 1),
        question: %Message.Question{host: "example.com", type: :a, class: :in},
        answer: answers,
        authority: authorities,
        additional: additionals
      }

      bytes = Message.encode(message)
      assert {:ok, decoded} = Message.decode(bytes)

      assert decoded.answer == answers
      assert decoded.authority == authorities
      assert decoded.additional == additionals
    end

    test "encode_for_udp/2 truncates and sets TC=1 when the response exceeds the budget" do
      records =
        for i <- 1..50 do
          %ExDns.Resource.A{
            name: "example.com",
            ttl: 60,
            class: :in,
            ipv4: {192, 0, 2, rem(i, 255)}
          }
        end

      message = %Message{
        header: blank_header(qr: 1, aa: 1, qc: 1, anc: length(records)),
        question: %Message.Question{host: "example.com", type: :a, class: :in},
        answer: records,
        authority: [],
        additional: []
      }

      bytes = Message.encode_for_udp(message, 512)
      assert byte_size(bytes) <= 512
      assert {:ok, decoded} = Message.decode(bytes)
      assert decoded.header.tc == 1
      assert decoded.answer == []
      assert decoded.question == message.question
    end

    test "encode_for_udp/2 leaves a fitting response untouched (TC=0)" do
      message = %Message{
        header: blank_header(qr: 1, aa: 1, qc: 1, anc: 1),
        question: %Message.Question{host: "example.com", type: :a, class: :in},
        answer: [
          %ExDns.Resource.A{name: "example.com", ttl: 60, class: :in, ipv4: {192, 0, 2, 1}}
        ],
        authority: [],
        additional: []
      }

      bytes = Message.encode_for_udp(message, 512)
      {:ok, decoded} = Message.decode(bytes)
      assert decoded.header.tc == 0
      assert length(decoded.answer) == 1
    end

    test "owner-name compression saves bytes when the same owner repeats" do
      # 10 A records with the same owner. Without compression the owner
      # is repeated 11 times (1 question + 10 answers) and would dominate
      # the message size. With compression each subsequent owner is
      # 2 bytes (a pointer) instead of the full 13 bytes for
      # "example.com\\0".
      records =
        for i <- 1..10 do
          %ExDns.Resource.A{
            name: "example.com",
            ttl: 60,
            class: :in,
            ipv4: {192, 0, 2, i}
          }
        end

      message = %Message{
        header: blank_header(qr: 1, aa: 1, qc: 1, anc: 10),
        question: %Message.Question{host: "example.com", type: :a, class: :in},
        answer: records,
        authority: [],
        additional: []
      }

      bytes = Message.encode(message)
      # Each compressed owner saves at least 11 bytes vs. fully-emitting
      # "example.com\\0". 10 answers compressed = ~110 bytes saved.
      naive_estimate = 12 + 17 + 10 * (13 + 10 + 4)
      assert byte_size(bytes) < naive_estimate - 80

      assert {:ok, decoded} = Message.decode(bytes)
      assert length(decoded.answer) == 10
      assert Enum.all?(decoded.answer, fn rr -> rr.name == "example.com" end)
    end

    test "round-trips a response carrying every implemented RR type" do
      records = [
        %ExDns.Resource.A{name: "host.example", ttl: 60, class: :in, ipv4: {198, 51, 100, 7}},
        %ExDns.Resource.AAAA{
          name: "host.example",
          ttl: 60,
          class: :in,
          ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}
        },
        %ExDns.Resource.NS{
          name: "example",
          ttl: 86_400,
          class: :in,
          server: "ns.example"
        },
        %ExDns.Resource.CNAME{
          name: "alias.example",
          ttl: 300,
          class: :in,
          server: "host.example"
        },
        %ExDns.Resource.PTR{
          name: "7.100.51.198.in-addr.arpa",
          ttl: 86_400,
          class: :in,
          pointer: "host.example"
        },
        %ExDns.Resource.MX{
          name: "example",
          ttl: 3600,
          class: :in,
          priority: 10,
          server: "mail.example"
        },
        %ExDns.Resource.TXT{
          name: "example",
          ttl: 60,
          class: :in,
          strings: ["v=spf1 -all"]
        },
        %ExDns.Resource.SRV{
          name: "_xmpp._tcp.example",
          ttl: 60,
          class: :in,
          priority: 10,
          weight: 60,
          port: 5222,
          target: "xmpp.example"
        },
        %ExDns.Resource.HINFO{
          name: "host.example",
          ttl: 86_400,
          class: :in,
          cpu: "x86_64",
          os: "Linux"
        },
        %ExDns.Resource.SOA{
          name: "example",
          ttl: 86_400,
          class: :in,
          mname: "ns.example",
          email: "hostmaster.example",
          serial: 1,
          refresh: 7200,
          retry: 3600,
          expire: 1_209_600,
          minimum: 3600
        },
        %ExDns.Resource.CAA{
          name: "example",
          ttl: 60,
          class: :in,
          flags: 0,
          tag: "issue",
          value: "letsencrypt.org"
        },
        %ExDns.Resource.DNAME{
          name: "old.example",
          ttl: 300,
          class: :in,
          target: "new.example"
        },
        %ExDns.Resource.SSHFP{
          name: "host.example",
          ttl: 60,
          class: :in,
          algorithm: 4,
          fp_type: 2,
          fingerprint: :crypto.hash(:sha256, "ed25519")
        },
        %ExDns.Resource.NAPTR{
          name: "+1-555-555-1212.e164.arpa",
          ttl: 60,
          class: :in,
          order: 100,
          preference: 50,
          flags: "U",
          services: "E2U+sip",
          regexp: "!^(.*)$!sip:\\1@example.com!",
          replacement: ""
        },
        %ExDns.Resource.URI{
          name: "_http._tcp.example",
          ttl: 60,
          class: :in,
          priority: 10,
          weight: 1,
          target: "https://example.com/"
        },
        %ExDns.Resource.LOC{
          name: "host.example",
          ttl: 60,
          class: :in,
          version: 0,
          size: 0x12,
          horiz_pre: 0x16,
          vert_pre: 0x13,
          latitude: 0x8000_0000 + 30_000_000,
          longitude: 0x8000_0000 - 90_000_000,
          altitude: 100_000_00
        },
        %ExDns.Resource.TLSA{
          name: "_443._tcp.host.example",
          ttl: 60,
          class: :in,
          cert_usage: 3,
          selector: 1,
          matching_type: 1,
          cert_data: :crypto.hash(:sha256, "x")
        },
        %ExDns.Resource.DS{
          name: "child.example",
          ttl: 86_400,
          class: :in,
          key_tag: 12_345,
          algorithm: 13,
          digest_type: 2,
          digest: :crypto.hash(:sha256, "k")
        },
        %ExDns.Resource.DNSKEY{
          name: "example",
          ttl: 86_400,
          class: :in,
          flags: 257,
          protocol: 3,
          algorithm: 13,
          public_key: :crypto.strong_rand_bytes(64)
        },
        %ExDns.Resource.RRSIG{
          name: "example",
          ttl: 86_400,
          class: :in,
          type_covered: :a,
          algorithm: 13,
          labels: 2,
          original_ttl: 60,
          signature_expiration: 1_700_000_000,
          signature_inception: 1_690_000_000,
          key_tag: 12_345,
          signer: "example",
          signature: :crypto.strong_rand_bytes(64)
        },
        %ExDns.Resource.NSEC{
          name: "example",
          ttl: 86_400,
          class: :in,
          next_domain: "next.example",
          type_bit_maps: <<0, 8, 0b00100010, 0, 0, 0, 0b00100000, 0, 0, 0>>
        },
        %ExDns.Resource.NSEC3{
          name: "example",
          ttl: 86_400,
          class: :in,
          hash_algorithm: 1,
          flags: 0,
          iterations: 10,
          salt: <<0xAA, 0xBB>>,
          next_hashed_owner: :crypto.hash(:sha, "label"),
          type_bit_maps: <<0, 6, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03>>
        },
        %ExDns.Resource.SVCB{
          name: "_https.example",
          ttl: 60,
          class: :in,
          priority: 1,
          target: "svc.example",
          params: [{1, <<2, "h2", 2, "h3">>}]
        },
        %ExDns.Resource.HTTPS{
          name: "example",
          ttl: 60,
          class: :in,
          priority: 1,
          target: "svc.example",
          params: [{1, <<2, "h3">>}]
        }
      ]

      message = %Message{
        header: blank_header(qr: 1, aa: 1, qc: 0, anc: length(records)),
        question: nil,
        answer: records,
        authority: [],
        additional: []
      }

      bytes = Message.encode(message)
      assert {:ok, decoded} = Message.decode(bytes)
      assert decoded.answer == records
    end
  end
end
