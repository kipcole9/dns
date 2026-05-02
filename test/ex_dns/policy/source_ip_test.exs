defmodule ExDns.Policy.SourceIpTest do
  use ExUnit.Case, async: true

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Policy.SourceIp
  alias ExDns.Request
  alias ExDns.Resource.A

  describe "cidr_match?/2" do
    test "matches an IPv4 address inside its CIDR" do
      assert SourceIp.cidr_match?({{198, 51, 100, 0}, 24}, {198, 51, 100, 7})
      refute SourceIp.cidr_match?({{198, 51, 100, 0}, 24}, {198, 51, 101, 7})
    end

    test "matches /0 always" do
      assert SourceIp.cidr_match?({{0, 0, 0, 0}, 0}, {1, 2, 3, 4})
    end

    test "matches /32 only on exact equality" do
      assert SourceIp.cidr_match?({{1, 2, 3, 4}, 32}, {1, 2, 3, 4})
      refute SourceIp.cidr_match?({{1, 2, 3, 4}, 32}, {1, 2, 3, 5})
    end

    test "matches IPv6" do
      assert SourceIp.cidr_match?({{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32}, {0x2001, 0xDB8, 0xABCD, 0, 0, 0, 0, 1})
      refute SourceIp.cidr_match?({{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 32}, {0x2002, 0xDB8, 0, 0, 0, 0, 0, 1})
    end
  end

  defp request_from(source_ip, qtype) do
    Request.new(
      %Message{
        header: %Header{
          id: 1,
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
        question: %Question{host: "anycast.example", type: qtype, class: :in},
        answer: [],
        authority: [],
        additional: []
      },
      source_ip: source_ip,
      source_port: 33_333,
      transport: :udp
    )
  end

  describe "resolve/2" do
    test "halts with the configured A answer when source IP matches" do
      state =
        SourceIp.init(
          table: [
            {{{198, 51, 100, 0}, 24}, %{a: {192, 0, 2, 1}}}
          ]
        )

      assert {:halt, response} =
               SourceIp.resolve(request_from({198, 51, 100, 7}, :a), state)

      assert response.header.qr == 1
      assert response.header.aa == 1
      assert [%A{ipv4: {192, 0, 2, 1}, name: "anycast.example"}] = response.answer
    end

    test "first matching CIDR wins" do
      state =
        SourceIp.init(
          table: [
            {{{198, 51, 100, 0}, 24}, %{a: {192, 0, 2, 1}}},
            {{{198, 51, 100, 0}, 16}, %{a: {192, 0, 2, 99}}}
          ]
        )

      assert {:halt, response} =
               SourceIp.resolve(request_from({198, 51, 100, 7}, :a), state)

      assert [%A{ipv4: {192, 0, 2, 1}}] = response.answer
    end

    test "returns :continue when no CIDR matches" do
      state = SourceIp.init(table: [{{{10, 0, 0, 0}, 8}, %{a: {1, 2, 3, 4}}}])
      assert :continue = SourceIp.resolve(request_from({203, 0, 113, 1}, :a), state)
    end

    test "returns :continue when source_ip is nil" do
      state = SourceIp.init(table: [{{{10, 0, 0, 0}, 8}, %{a: {1, 2, 3, 4}}}])

      request = %Request{request_from({10, 0, 0, 1}, :a) | source_ip: nil}
      assert :continue = SourceIp.resolve(request, state)
    end

    test "returns :continue when matched CIDR has no answer for the qtype" do
      state =
        SourceIp.init(
          table: [
            {{{198, 51, 100, 0}, 24}, %{a: {192, 0, 2, 1}}}
          ]
        )

      # Configured for A, queried for AAAA → continue.
      assert :continue =
               SourceIp.resolve(request_from({198, 51, 100, 7}, :aaaa), state)
    end

    test "synthesizes multiple A records when given a list" do
      state =
        SourceIp.init(
          table: [{{{198, 51, 100, 0}, 24}, %{a: [{192, 0, 2, 1}, {192, 0, 2, 2}]}}]
        )

      {:halt, response} = SourceIp.resolve(request_from({198, 51, 100, 7}, :a), state)
      assert length(response.answer) == 2
    end
  end
end
