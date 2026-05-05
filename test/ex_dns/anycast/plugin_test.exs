defmodule ExDns.Anycast.PluginTest do
  @moduledoc """
  End-to-end tests for the Anycast plugin via the
  ExDns.Resolver.Plugins pipeline. Validates per-region
  CIDR routing, qtype filtering, qname-suffix scoping, and
  fall-through to the underlying resolver when nothing
  matches.
  """

  use ExUnit.Case, async: false

  alias ExDns.Anycast.Plugin
  alias ExDns.Plugin.Registry
  alias ExDns.Resolver.Plugins, as: ResolverPlugins
  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Request
  alias ExDns.Resource.{A, AAAA}

  defmodule StubUnderlying do
    def resolve(%Request{message: msg}), do: resolve(msg)

    def resolve(%Message{} = msg) do
      %Message{
        msg
        | header: %Header{msg.header | qr: 1, aa: 0, ra: 1, rc: 0, anc: 1},
          answer: [%A{name: "fallthrough.test", ttl: 60, class: :in, ipv4: {7, 7, 7, 7}}]
      }
    end
  end

  setup do
    Registry.clear()

    previous_anycast = Application.get_env(:ex_dns, :anycast)
    previous_pipeline = Application.get_env(:ex_dns, :plugin_pipeline)

    Application.put_env(:ex_dns, :anycast,
      regions: [
        %{
          id: :eu,
          cidrs: [{{198, 51, 100, 0}, 24}],
          qname_suffix: "cdn.example",
          answers: %{
            a: {192, 0, 2, 1},
            aaaa: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}
          }
        },
        %{
          id: :us,
          cidrs: [{{203, 0, 113, 0}, 24}],
          qname_suffix: "cdn.example",
          answers: %{a: [{192, 0, 2, 2}, {192, 0, 2, 3}]}
        }
      ]
    )

    Application.put_env(:ex_dns, :plugin_pipeline, underlying: StubUnderlying)

    :ok = Registry.register(Plugin)

    on_exit(fn ->
      Registry.clear()

      case previous_anycast do
        nil -> Application.delete_env(:ex_dns, :anycast)
        v -> Application.put_env(:ex_dns, :anycast, v)
      end

      case previous_pipeline do
        nil -> Application.delete_env(:ex_dns, :plugin_pipeline)
        v -> Application.put_env(:ex_dns, :plugin_pipeline, v)
      end
    end)

    :ok
  end

  defp request(source_ip, qname, qtype \\ :a) do
    msg = %Message{
      header: %Header{
        id: 1,
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

    Request.new(msg, source_ip: source_ip, source_port: nil, transport: :udp)
  end

  test "EU client → EU answer (single A)" do
    response = ResolverPlugins.resolve(request({198, 51, 100, 5}, "host.cdn.example"))
    assert response.header.aa == 1
    assert response.header.rc == 0
    assert [%A{ipv4: {192, 0, 2, 1}}] = response.answer
  end

  test "US client → US answer (multiple A records)" do
    response = ResolverPlugins.resolve(request({203, 0, 113, 5}, "host.cdn.example"))
    assert response.header.aa == 1

    assert [
             %A{ipv4: {192, 0, 2, 2}},
             %A{ipv4: {192, 0, 2, 3}}
           ] = response.answer
  end

  test "EU client + AAAA → IPv6 answer" do
    response = ResolverPlugins.resolve(request({198, 51, 100, 5}, "host.cdn.example", :aaaa))
    assert [%AAAA{ipv6: {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}}] = response.answer
  end

  test "US client + AAAA → no AAAA configured → falls through to underlying" do
    response = ResolverPlugins.resolve(request({203, 0, 113, 5}, "host.cdn.example", :aaaa))
    assert [%A{ipv4: {7, 7, 7, 7}}] = response.answer
  end

  test "client outside any region's CIDR → falls through" do
    response = ResolverPlugins.resolve(request({1, 2, 3, 4}, "host.cdn.example"))
    assert [%A{ipv4: {7, 7, 7, 7}}] = response.answer
  end

  test "client inside region CIDR but outside the zone suffix → falls through" do
    response = ResolverPlugins.resolve(request({198, 51, 100, 5}, "elsewhere.test"))
    assert [%A{ipv4: {7, 7, 7, 7}}] = response.answer
  end

  test "TXT query (not in answers) → falls through" do
    response = ResolverPlugins.resolve(request({198, 51, 100, 5}, "host.cdn.example", :txt))
    assert [%A{ipv4: {7, 7, 7, 7}}] = response.answer
  end

  test "regions resource returns all regions in UI shape" do
    {:ok, rows} = Plugin.get_resource(:regions)
    assert length(rows) == 2

    eu = Enum.find(rows, fn r -> r["id"] == "eu" end)
    assert eu["cidrs"] == ["198.51.100.0/24"]
    assert eu["qname_suffix"] == "cdn.example"
    assert eu["answers"] =~ "a="
    assert eu["answers"] =~ "aaaa="
  end
end
