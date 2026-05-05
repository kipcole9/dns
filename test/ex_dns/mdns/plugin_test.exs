defmodule ExDns.MDNS.PluginTest do
  @moduledoc """
  Verifies the mDNS plugin module — its metadata shape and
  resource translation. The discoverer is stubbed so the
  test never opens an mDNS socket.
  """

  use ExUnit.Case, async: false

  alias ExDns.MDNS.Plugin

  defmodule StubDiscoverer do
    @moduledoc false

    def install(snapshot) do
      :persistent_term.put(__MODULE__, snapshot)

      case Process.whereis(ExDns.MDNS.Visualizer.Discoverer) do
        nil ->
          {:ok, pid} =
            GenServer.start_link(
              __MODULE__,
              :ok,
              name: ExDns.MDNS.Visualizer.Discoverer
            )

          {:ok, pid}

        _pid ->
          :ok
      end
    end

    def uninstall do
      case Process.whereis(ExDns.MDNS.Visualizer.Discoverer) do
        nil -> :ok
        pid -> GenServer.stop(pid)
      end

      :persistent_term.erase(__MODULE__)
      :ok
    end

    use GenServer
    @impl true
    def init(_), do: {:ok, %{}}

    @impl true
    def handle_call(:snapshot, _from, state) do
      {:reply, :persistent_term.get(__MODULE__, %{services: %{}}), state}
    end
  end

  setup do
    snapshot = %{
      cycles: 4,
      last_refresh: ~U[2026-05-06 06:00:00Z],
      types: ["_http._tcp.local"],
      services: %{
        "_http._tcp.local" => %{
          "MyPrinter._http._tcp.local" => %{
            srv: %{target: "myprinter.local.", port: 80},
            txt: %{strings: ["model=hp"]},
            addresses: [{192, 168, 1, 10}]
          }
        }
      }
    }

    StubDiscoverer.install(snapshot)
    on_exit(fn -> StubDiscoverer.uninstall() end)
    :ok
  end

  describe "metadata/0" do
    test "declares slug, name, version, ui block" do
      meta = Plugin.metadata()

      assert meta.slug == :mdns
      assert is_binary(meta.name)
      assert is_binary(meta.version)
      assert :services in meta.ui.resources
      assert :summary in meta.ui.resources
      assert meta.ui.view == :table
    end
  end

  describe "get_resource/1" do
    test ":services returns one row per discovered instance" do
      assert {:ok, [row]} = Plugin.get_resource(:services)

      assert row["type"] == "_http._tcp.local"
      assert row["instance"] == "MyPrinter._http._tcp.local"
      assert row["target"] == "myprinter.local"
      assert row["port"] == 80
      assert row["addresses"] == ["192.168.1.10"]
      assert row["txt"] == ["model=hp"]
    end

    test ":summary returns aggregate counts" do
      assert {:ok, summary} = Plugin.get_resource(:summary)

      assert summary["cycles"] == 4
      assert summary["types"] == ["_http._tcp.local"]
      assert summary["total_instances"] == 1
      assert summary["last_refresh"] =~ "2026-05-06"
    end

    test "unknown resource returns :not_found" do
      assert {:error, :not_found} = Plugin.get_resource(:nope)
    end
  end
end
