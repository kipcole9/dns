# Resolver benchmark — measure end-to-end query handling on
# the authoritative path with a small in-memory zone.
#
# Run with:
#   MIX_ENV=bench mix run bench/resolver.exs

alias ExDns.Message
alias ExDns.Message.{Header, Question}
alias ExDns.Resource.{A, NS, SOA}
alias ExDns.Resolver.Default
alias ExDns.Storage

# Make sure the application is up so the storage layer is wired.
{:ok, _} = Application.ensure_all_started(:ex_dns)

Storage.init()
Enum.each(Storage.zones(), &Storage.delete_zone/1)

records =
  [
    %SOA{
      name: "bench.test",
      ttl: 3600,
      class: :in,
      mname: "ns",
      email: "h",
      serial: 1,
      refresh: 3600,
      retry: 600,
      expire: 86_400,
      minimum: 60
    },
    %NS{name: "bench.test", ttl: 3600, class: :in, server: "ns.bench.test"}
  ] ++
    for i <- 1..50 do
      %A{name: "host#{i}.bench.test", ttl: 60, class: :in, ipv4: {10, 0, 0, rem(i, 256)}}
    end

Storage.put_zone("bench.test", records)

defmodule Bench.Q do
  def query(qname, qtype) do
    %Message{
      header: %Header{
        id: 0xCAFE,
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
        auc: 0,
        adc: 0
      },
      question: %Question{host: qname, type: qtype, class: :in},
      answer: [],
      authority: [],
      additional: []
    }
  end
end

hit_query = Bench.Q.query("host1.bench.test", :a)
miss_query = Bench.Q.query("does-not-exist.bench.test", :a)
nodata_query = Bench.Q.query("host1.bench.test", :mx)
delegation_query = Bench.Q.query("bench.test", :ns)

Benchee.run(
  %{
    "resolve A (cache hit)" => fn -> Default.resolve(hit_query) end,
    "resolve A (NXDOMAIN)" => fn -> Default.resolve(miss_query) end,
    "resolve MX (NODATA)" => fn -> Default.resolve(nodata_query) end,
    "resolve NS (apex)" => fn -> Default.resolve(delegation_query) end
  },
  time: 2,
  warmup: 1,
  print: [configuration: false]
)
