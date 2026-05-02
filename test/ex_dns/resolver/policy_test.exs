defmodule ExDns.Resolver.PolicyTest do
  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Request
  alias ExDns.Resolver.Policy
  alias ExDns.Resource.{A, SOA}
  alias ExDns.Storage

  setup do
    Storage.init()
    Enum.each(Storage.zones(), &Storage.delete_zone/1)
    Application.delete_env(:ex_dns, :policies)
    Application.delete_env(:ex_dns, :underlying_resolver)
    Policy.reset_chain()
    on_exit(fn ->
      Application.delete_env(:ex_dns, :policies)
      Application.delete_env(:ex_dns, :underlying_resolver)
      Policy.reset_chain()
    end)

    :ok
  end

  defp request(source_ip, qname, qtype) do
    Request.new(
      %Message{
        header: %Header{
          id: 7,
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
      },
      source_ip: source_ip,
      transport: :udp
    )
  end

  test "policy halt short-circuits the chain and the result is returned verbatim" do
    Application.put_env(:ex_dns, :policies, [
      {ExDns.Policy.SourceIp,
       table: [
         {{{198, 51, 100, 0}, 24}, %{a: {192, 0, 2, 1}}}
       ]}
    ])

    Policy.reset_chain()

    response = Policy.resolve(request({198, 51, 100, 7}, "anything.example", :a))
    assert response.header.aa == 1
    assert [%A{ipv4: {192, 0, 2, 1}}] = response.answer
  end

  test "policy :continue falls through to the underlying resolver" do
    Storage.put_zone("authoritative.test", [
      %SOA{
        name: "authoritative.test",
        ttl: 86_400,
        class: :internet,
        mname: "ns.authoritative.test",
        email: "admin.authoritative.test",
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minimum: 3600
      },
      %A{name: "authoritative.test", ttl: 60, class: :internet, ipv4: {10, 0, 0, 1}}
    ])

    Application.put_env(:ex_dns, :policies, [
      # The CIDR doesn't match the source we'll use, so the policy
      # falls through to the default resolver.
      {ExDns.Policy.SourceIp,
       table: [{{{198, 51, 100, 0}, 24}, %{a: {192, 0, 2, 1}}}]}
    ])

    Policy.reset_chain()

    response = Policy.resolve(request({10, 0, 0, 99}, "authoritative.test", :a))

    assert response.header.aa == 1
    assert [%A{ipv4: {10, 0, 0, 1}}] = response.answer
  end

  test "the chain composes: first policy continues, second halts" do
    defmodule AlwaysContinue do
      @behaviour ExDns.Policy
      @impl true
      def init(_), do: nil
      @impl true
      def resolve(_request, _state), do: :continue
    end

    Application.put_env(:ex_dns, :policies, [
      {AlwaysContinue, []},
      {ExDns.Policy.SourceIp,
       table: [{{{198, 51, 100, 0}, 24}, %{a: {192, 0, 2, 99}}}]}
    ])

    Policy.reset_chain()

    response = Policy.resolve(request({198, 51, 100, 1}, "anything.example", :a))
    assert [%A{ipv4: {192, 0, 2, 99}}] = response.answer
  end

  test "an empty policy chain is just the underlying resolver" do
    Storage.put_zone("plain.test", [
      %SOA{
        name: "plain.test",
        ttl: 86_400,
        class: :internet,
        mname: "ns.plain.test",
        email: "admin.plain.test",
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 1_209_600,
        minimum: 3600
      },
      %A{name: "plain.test", ttl: 60, class: :internet, ipv4: {172, 16, 0, 1}}
    ])

    Application.put_env(:ex_dns, :policies, [])
    Policy.reset_chain()

    response = Policy.resolve(request({1, 2, 3, 4}, "plain.test", :a))
    assert [%A{ipv4: {172, 16, 0, 1}}] = response.answer
  end
end
