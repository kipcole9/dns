# Wire codec benchmark — encode and decode common DNS message
# shapes so we can spot regressions in the bitstring-based
# message decoder.
#
# Run with:
#   MIX_ENV=bench mix run bench/wire_codec.exs

alias ExDns.Message
alias ExDns.Message.{Header, Question}
alias ExDns.Resource.{A, AAAA, NS}

defmodule Bench.Fixtures do
  def query(qname, qtype) do
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

  def small_response do
    %Message{
      query("example.test", :a)
      | header: %Header{
          id: 0xCAFE,
          qr: 1,
          oc: 0,
          aa: 1,
          tc: 0,
          rd: 0,
          ra: 0,
          ad: 0,
          cd: 0,
          rc: 0,
          qc: 1,
          anc: 1,
          auc: 0,
          adc: 0
        },
        answer: [%A{name: "example.test", ttl: 60, class: :in, ipv4: {198, 51, 100, 7}}]
    }
  end

  def large_response do
    answer =
      for i <- 1..30 do
        %A{name: "host#{i}.example.test", ttl: 60, class: :in, ipv4: {10, 0, 0, rem(i, 256)}}
      end

    %Message{
      query("example.test", :a)
      | header: %Header{
          id: 0xCAFE,
          qr: 1,
          oc: 0,
          aa: 1,
          tc: 0,
          rd: 0,
          ra: 0,
          ad: 0,
          cd: 0,
          rc: 0,
          qc: 1,
          anc: length(answer),
          auc: 4,
          adc: 8
        },
        answer: answer,
        authority: [
          %NS{name: "example.test", ttl: 60, class: :in, server: "ns1.example.test"},
          %NS{name: "example.test", ttl: 60, class: :in, server: "ns2.example.test"},
          %NS{name: "example.test", ttl: 60, class: :in, server: "ns3.example.test"},
          %NS{name: "example.test", ttl: 60, class: :in, server: "ns4.example.test"}
        ],
        additional: [
          %A{name: "ns1.example.test", ttl: 60, class: :in, ipv4: {10, 1, 0, 1}},
          %A{name: "ns2.example.test", ttl: 60, class: :in, ipv4: {10, 1, 0, 2}},
          %A{name: "ns3.example.test", ttl: 60, class: :in, ipv4: {10, 1, 0, 3}},
          %A{name: "ns4.example.test", ttl: 60, class: :in, ipv4: {10, 1, 0, 4}},
          %AAAA{name: "ns1.example.test", ttl: 60, class: :in, ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}},
          %AAAA{name: "ns2.example.test", ttl: 60, class: :in, ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 2}},
          %AAAA{name: "ns3.example.test", ttl: 60, class: :in, ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 3}},
          %AAAA{name: "ns4.example.test", ttl: 60, class: :in, ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 4}}
        ]
    }
  end
end

small_query = Bench.Fixtures.query("example.test", :a)
small_response = Bench.Fixtures.small_response()
large_response = Bench.Fixtures.large_response()

small_query_bytes = Message.encode(small_query)
small_response_bytes = Message.encode(small_response)
large_response_bytes = Message.encode(large_response)

IO.puts("Encoded sizes:")
IO.puts("  small query:    #{byte_size(small_query_bytes)} bytes")
IO.puts("  small response: #{byte_size(small_response_bytes)} bytes")
IO.puts("  large response: #{byte_size(large_response_bytes)} bytes")
IO.puts("")

Benchee.run(
  %{
    "encode small query" => fn -> Message.encode(small_query) end,
    "encode small response" => fn -> Message.encode(small_response) end,
    "encode large response" => fn -> Message.encode(large_response) end,
    "decode small query" => fn -> {:ok, _} = Message.decode(small_query_bytes) end,
    "decode small response" => fn -> {:ok, _} = Message.decode(small_response_bytes) end,
    "decode large response" => fn -> {:ok, _} = Message.decode(large_response_bytes) end
  },
  time: 2,
  warmup: 1,
  memory_time: 1,
  print: [configuration: false]
)
