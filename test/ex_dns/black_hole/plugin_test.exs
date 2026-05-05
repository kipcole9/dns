defmodule ExDns.BlackHole.PluginTest do
  @moduledoc """
  End-to-end test of the BlackHole plugin: the route table
  routes a query to it; the policy hook consults the compiled
  set, allowlist, and denylist; and resources surface to the
  API correctly.
  """

  use ExUnit.Case, async: false

  alias ExDns.BlackHole.{Plugin, Set, Storage}
  alias ExDns.Plugin.Registry
  alias ExDns.Resolver.Plugins, as: ResolverPlugins
  alias ExDns.Message
  alias ExDns.Message.{Header, Question}
  alias ExDns.Request
  alias ExDns.Resource.A

  defmodule StubUnderlying do
    def resolve(%Request{message: msg}), do: resolve(msg)

    def resolve(%Message{} = msg) do
      %Message{
        msg
        | header: %Header{msg.header | qr: 1, aa: 0, ra: 1, rc: 0, anc: 1},
          answer: [%A{name: "ok.test", ttl: 60, class: :in, ipv4: {7, 7, 7, 7}}]
      }
    end
  end

  setup do
    Registry.clear()
    Set.clear()

    path =
      Path.join(
        System.tmp_dir!(),
        "ex_dns_blackhole_plugin_#{System.unique_integer([:positive])}.db"
      )

    previous_bh = Application.get_env(:ex_dns, :black_hole)
    previous_pp = Application.get_env(:ex_dns, :plugin_pipeline)

    Application.put_env(:ex_dns, :black_hole,
      storage: {ExDns.BlackHole.Storage.SQLite, [path: path]},
      default_block_response: :nxdomain
    )

    Application.put_env(:ex_dns, :plugin_pipeline, underlying: StubUnderlying)

    :ok = Storage.init()

    {:ok, _} =
      Storage.put_group(%{
        "name" => "home",
        "enabled" => true,
        "cidrs" => ["192.168.1.0/24"],
        "blocklist_ids" => []
      })

    :ok = Registry.register(Plugin)

    on_exit(fn ->
      Registry.clear()
      Set.clear()
      File.rm(path)
      File.rm(path <> "-wal")
      File.rm(path <> "-shm")

      case previous_bh do
        nil -> Application.delete_env(:ex_dns, :black_hole)
        v -> Application.put_env(:ex_dns, :black_hole, v)
      end

      case previous_pp do
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

  test "client outside the home CIDR → underlying resolver" do
    response = ResolverPlugins.resolve(request({1, 2, 3, 4}, "ads.example"))
    assert [%A{ipv4: {7, 7, 7, 7}}] = response.answer
  end

  test "home client + clean qname → underlying resolver" do
    response = ResolverPlugins.resolve(request({192, 168, 1, 50}, "ok.test"))
    assert [%A{ipv4: {7, 7, 7, 7}}] = response.answer
  end

  test "home client + blocked qname → NXDOMAIN" do
    Set.install(Set.compile(["ads.example"]))

    response = ResolverPlugins.resolve(request({192, 168, 1, 50}, "ads.example"))
    assert response.header.rc == 3
    assert response.answer == []
  end

  test "home client + denylist match → NXDOMAIN" do
    {:ok, _} = Storage.put_deny(%{"domain" => "tracker.example"})

    response = ResolverPlugins.resolve(request({192, 168, 1, 50}, "tracker.example"))
    assert response.header.rc == 3
  end

  test "allowlist takes precedence over the compiled set" do
    Set.install(Set.compile(["maybe-ad.example"]))
    {:ok, _} = Storage.put_allow(%{"domain" => "maybe-ad.example"})

    response = ResolverPlugins.resolve(request({192, 168, 1, 50}, "maybe-ad.example"))
    # Falls through to underlying.
    assert [%A{}] = response.answer
  end

  test "wildcard match blocks subdomains" do
    Set.install(Set.compile(["*.ads.example"]))

    response =
      ResolverPlugins.resolve(request({192, 168, 1, 50}, "tracker.ads.example"))

    assert response.header.rc == 3
  end

  test "get_resource(:overview) returns the dashboard payload" do
    {:ok, payload} = Plugin.get_resource(:overview)
    assert is_map(payload)
    assert Map.has_key?(payload, "queries_today")
    assert Map.has_key?(payload, "active_blocklists")
  end
end
