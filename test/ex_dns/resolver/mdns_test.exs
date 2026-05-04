defmodule ExDns.Resolver.MDNSTest do
  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Request
  alias ExDns.Resolver.MDNS
  alias ExDns.Resource.A
  alias ExDns.Storage

  setup do
    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)
    on_exit(fn -> Enum.each(Storage.zones(), &Storage.delete_zone/1) end)
    :ok
  end

  defp seed_local_zone do
    Storage.put_zone("local", [
      %A{name: "host1.local", ttl: 60, class: :internet, ipv4: {192, 168, 1, 10}}
    ])
  end

  defp request_for(host, qtype, opts \\ []) do
    Request.new(
      %Message{
        header: %Header{
          id: 0,
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
        question: %Question{
          host: host,
          type: qtype,
          class: :in,
          unicast_response: Keyword.get(opts, :unicast_response, false)
        },
        answer: [],
        authority: [],
        additional: []
      },
      source_ip: Keyword.get(opts, :source_ip, {192, 168, 1, 100}),
      source_port: 5353,
      transport: :mdns
    )
  end

  describe "resolve/1" do
    test "answers a known .local A query as multicast" do
      seed_local_zone()
      assert {:multicast, response} = MDNS.resolve(request_for("host1.local", :a))
      assert response.header.qr == 1
      assert response.header.aa == 1
      assert response.header.id == 0
      assert [%A{ipv4: {192, 168, 1, 10}, class: :in}] = response.answer
    end

    test "honours the QU bit by routing the response unicast" do
      seed_local_zone()

      assert {:unicast, response} =
               MDNS.resolve(request_for("host1.local", :a, unicast_response: true))

      assert response.header.aa == 1
    end

    test "stays silent (returns :no_answer) for non-.local names" do
      seed_local_zone()
      assert :no_answer = MDNS.resolve(request_for("host1.example.com", :a))
    end

    test "stays silent for unknown .local names" do
      seed_local_zone()
      assert :no_answer = MDNS.resolve(request_for("nope.local", :a))
    end

    test "stays silent when the name exists but the type does not (NODATA)" do
      seed_local_zone()
      assert :no_answer = MDNS.resolve(request_for("host1.local", :aaaa))
    end

    test "stays silent on a query with no question section" do
      empty_request =
        Request.new(
          %Message{
            header: %Header{
              id: 0,
              qr: 0,
              oc: 0,
              aa: 0,
              tc: 0,
              rd: 0,
              ra: 0,
              ad: 0,
              cd: 0,
              rc: 0,
              qc: 0,
              anc: 0,
              auc: 0,
              adc: 0
            },
            question: nil,
            answer: [],
            authority: [],
            additional: []
          },
          transport: :mdns
        )

      assert :no_answer = MDNS.resolve(empty_request)
    end
  end
end
