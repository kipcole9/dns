defmodule ExDns.Resolver.PluginsTest do
  @moduledoc """
  Tests for the plugin-pipeline resolver wrapper. Verifies
  that pass-through, `:cont`, halts, and synthetic responses
  all work end-to-end with a stubbed underlying resolver.
  """

  use ExUnit.Case, async: false

  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Plugin.Registry
  alias ExDns.Request
  alias ExDns.Resolver.Plugins
  alias ExDns.Resource.A

  defmodule StubUnderlying do
    def resolve(%Request{message: msg}), do: resolve(msg)

    def resolve(%Message{} = msg) do
      %Message{
        msg
        | header: %Header{msg.header | qr: 1, aa: 0, ra: 1, rc: 0, anc: 1},
          answer: [%A{name: "underlying.test", ttl: 60, class: :in, ipv4: {7, 7, 7, 7}}]
      }
    end
  end

  defmodule BlockingPlugin do
    @behaviour ExDns.Plugin
    @behaviour ExDns.Plugin.Policy

    @impl ExDns.Plugin
    def metadata, do: %{slug: :blocker, name: "Blocker", version: "1"}

    @impl ExDns.Plugin.Policy
    def routes do
      [%{cidrs: [{{192, 168, 1, 0}, 24}], qtypes: :any, priority: 50}]
    end

    @impl ExDns.Plugin.Policy
    def policy_resolve(_request, _route), do: {:halt, :nxdomain}
  end

  defmodule RedirectPlugin do
    @behaviour ExDns.Plugin
    @behaviour ExDns.Plugin.Policy

    @impl ExDns.Plugin
    def metadata, do: %{slug: :redirect, name: "Redirect", version: "1"}

    @impl ExDns.Plugin.Policy
    def routes do
      [%{cidrs: [{{10, 0, 0, 0}, 8}], qtypes: [:a], priority: 50}]
    end

    @impl ExDns.Plugin.Policy
    def policy_resolve(_request, _route), do: {:halt, {:redirect, {1, 2, 3, 4}}}
  end

  defmodule ContPlugin do
    @behaviour ExDns.Plugin
    @behaviour ExDns.Plugin.Policy

    @impl ExDns.Plugin
    def metadata, do: %{slug: :cont_plugin, name: "Cont", version: "1"}

    @impl ExDns.Plugin.Policy
    def routes do
      [%{cidrs: [{{172, 16, 0, 0}, 12}], qtypes: :any, priority: 50}]
    end

    @impl ExDns.Plugin.Policy
    def policy_resolve(_request, _route), do: :cont
  end

  setup do
    Registry.clear()
    previous = Application.get_env(:ex_dns, :plugin_pipeline)
    Application.put_env(:ex_dns, :plugin_pipeline, underlying: StubUnderlying)

    on_exit(fn ->
      Registry.clear()

      case previous do
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

  describe "pass-through floor" do
    test "no plugins → defer to underlying" do
      response = Plugins.resolve(request({1, 2, 3, 4}, "anything.test"))
      assert [%A{ipv4: {7, 7, 7, 7}}] = response.answer
    end

    test "plugins registered but route doesn't match → defer to underlying" do
      Registry.register(BlockingPlugin)
      response = Plugins.resolve(request({1, 2, 3, 4}, "anything.test"))
      assert [%A{ipv4: {7, 7, 7, 7}}] = response.answer
    end
  end

  describe "halt actions" do
    test "{:halt, :nxdomain} → rcode 3, empty answer, AA=1" do
      Registry.register(BlockingPlugin)

      response = Plugins.resolve(request({192, 168, 1, 50}, "ads.test"))
      assert response.header.rc == 3
      assert response.header.aa == 1
      assert response.answer == []
    end

    test "{:halt, {:redirect, ip}} → A record pointing at ip" do
      Registry.register(RedirectPlugin)

      response = Plugins.resolve(request({10, 1, 2, 3}, "x.test", :a))
      assert response.header.rc == 0
      assert [%A{name: "x.test", ipv4: {1, 2, 3, 4}}] = response.answer
    end
  end

  describe "cont action" do
    test "matched plugin returning :cont falls through to underlying" do
      Registry.register(ContPlugin)
      response = Plugins.resolve(request({172, 16, 5, 5}, "x.test"))
      assert [%A{ipv4: {7, 7, 7, 7}}] = response.answer
    end
  end

  describe "telemetry" do
    test "fires :match with the matched plugin's slug" do
      Registry.register(BlockingPlugin)
      test_pid = self()

      :telemetry.attach(
        "plugins-test-#{System.unique_integer([:positive])}",
        [:ex_dns, :resolver, :plugins, :match],
        fn _, _, metadata, _ -> send(test_pid, {:event, metadata}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach("plugins-test") end)

      Plugins.resolve(request({192, 168, 1, 50}, "x.test"))
      assert_receive {:event, %{decision: :plugin_cont, plugin_slug: :blocker}}
      assert_receive {:event, %{decision: :plugin_halt, plugin_slug: :blocker}}

      Plugins.resolve(request({1, 2, 3, 4}, "x.test"))
      assert_receive {:event, %{decision: :passthru, plugin_slug: nil}}
    end
  end
end
