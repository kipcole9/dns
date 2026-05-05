defmodule ExDns.Plugin.RegistryRoutingTest do
  @moduledoc """
  Tests for the route-table additions on `ExDns.Plugin.Registry`:
  `match/1` (longest-prefix + priority + registration order)
  and `update_routes/2`.
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Plugin.Registry
  alias ExDns.Request

  defmodule HomePlugin do
    @behaviour ExDns.Plugin
    @behaviour ExDns.Plugin.Policy

    @impl ExDns.Plugin
    def metadata do
      %{slug: :home, name: "Home", version: "1"}
    end

    @impl ExDns.Plugin.Policy
    def routes do
      [%{cidrs: [{{192, 168, 1, 0}, 24}], qtypes: :any, priority: 50}]
    end

    @impl ExDns.Plugin.Policy
    def policy_resolve(_, _), do: :cont
  end

  defmodule WideAnalyticsPlugin do
    @behaviour ExDns.Plugin
    @behaviour ExDns.Plugin.Policy

    @impl ExDns.Plugin
    def metadata, do: %{slug: :analytics, name: "Analytics", version: "1"}

    @impl ExDns.Plugin.Policy
    def routes do
      [%{cidrs: [{{0, 0, 0, 0}, 0}], qtypes: :any, priority: 1}]
    end

    @impl ExDns.Plugin.Policy
    def policy_resolve(_, _), do: :cont
  end

  defmodule AnycastPlugin do
    @behaviour ExDns.Plugin
    @behaviour ExDns.Plugin.Policy

    @impl ExDns.Plugin
    def metadata, do: %{slug: :anycast, name: "Anycast", version: "1"}

    @impl ExDns.Plugin.Policy
    def routes do
      [
        %{
          cidrs: [{{203, 0, 113, 0}, 24}],
          qtypes: [:a, :aaaa],
          qname_suffix: "cdn.example",
          priority: 50
        }
      ]
    end

    @impl ExDns.Plugin.Policy
    def policy_resolve(_, _), do: :cont
  end

  setup do
    Registry.clear()
    on_exit(fn -> Registry.clear() end)
    :ok
  end

  defp request(source_ip, qname, qtype) do
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

  describe "match/1 with no plugins" do
    test "returns :none — pass-through floor" do
      assert :none = Registry.match(request({1, 2, 3, 4}, "x.test", :a))
    end
  end

  describe "match/1 with a single CIDR-scoped plugin" do
    setup do
      Registry.register(HomePlugin)
      :ok
    end

    test "matches a client inside the CIDR" do
      assert {:ok, HomePlugin, _route} =
               Registry.match(request({192, 168, 1, 50}, "x.test", :a))
    end

    test "no match for clients outside the CIDR" do
      assert :none = Registry.match(request({10, 0, 0, 1}, "x.test", :a))
    end
  end

  describe "longest-prefix-wins tiebreak" do
    test "specific /24 beats catch-all /0 even when /0 has equal priority" do
      Registry.register(WideAnalyticsPlugin)
      Registry.register(HomePlugin)

      assert {:ok, HomePlugin, _} =
               Registry.match(request({192, 168, 1, 50}, "x.test", :a))
    end

    test "catch-all still matches clients outside the specific CIDR" do
      Registry.register(WideAnalyticsPlugin)
      Registry.register(HomePlugin)

      assert {:ok, WideAnalyticsPlugin, _} =
               Registry.match(request({10, 0, 0, 1}, "x.test", :a))
    end
  end

  describe "qtype filtering" do
    setup do
      Registry.register(AnycastPlugin)
      :ok
    end

    test "matches A queries (in declared qtypes)" do
      assert {:ok, AnycastPlugin, _} =
               Registry.match(request({203, 0, 113, 5}, "host.cdn.example", :a))
    end

    test "no match for TXT queries (not in declared qtypes)" do
      assert :none =
               Registry.match(request({203, 0, 113, 5}, "host.cdn.example", :txt))
    end
  end

  describe "qname_suffix filtering" do
    setup do
      Registry.register(AnycastPlugin)
      :ok
    end

    test "matches qnames inside the suffix" do
      assert {:ok, AnycastPlugin, _} =
               Registry.match(request({203, 0, 113, 5}, "host.cdn.example", :a))
    end

    test "no match for qnames outside the suffix" do
      assert :none =
               Registry.match(request({203, 0, 113, 5}, "elsewhere.test", :a))
    end
  end

  describe "update_routes/2" do
    test "replaces routes atomically" do
      Registry.register(HomePlugin)

      assert {:ok, HomePlugin, _} =
               Registry.match(request({192, 168, 1, 50}, "x.test", :a))

      :ok =
        Registry.update_routes(:home, [
          %{cidrs: [{{10, 0, 0, 0}, 8}], qtypes: :any, priority: 50}
        ])

      assert :none = Registry.match(request({192, 168, 1, 50}, "x.test", :a))

      assert {:ok, HomePlugin, _} =
               Registry.match(request({10, 1, 2, 3}, "x.test", :a))
    end

    test "returns :unknown_plugin for unknown slug" do
      assert {:error, :unknown_plugin} = Registry.update_routes(:nope, [])
    end
  end
end
