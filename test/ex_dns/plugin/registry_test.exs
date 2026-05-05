defmodule ExDns.Plugin.RegistryTest do
  @moduledoc """
  Verifies the in-process plugin registry: register, list,
  get, get_resource, and graceful failure for invalid plugin
  modules.
  """

  use ExUnit.Case, async: false

  alias ExDns.Plugin.Registry

  defmodule SamplePlugin do
    @behaviour ExDns.Plugin

    @impl true
    def metadata do
      %{
        slug: :sample,
        name: "Sample plugin",
        version: "1.2.3",
        ui: %{title: "Sample", view: :table, resources: [:rows]}
      }
    end

    @impl true
    def get_resource(:rows), do: {:ok, [%{"a" => 1}, %{"a" => 2}]}
    def get_resource(_), do: {:error, :not_found}
  end

  defmodule MetadataOnlyPlugin do
    @behaviour ExDns.Plugin

    @impl true
    def metadata, do: %{slug: :only_metadata, name: "Only", version: "0.0.1"}
  end

  setup do
    Registry.clear()
    on_exit(fn -> Registry.clear() end)
    :ok
  end

  describe "register/1" do
    test "adds the plugin's metadata to the registry" do
      assert :ok = Registry.register(SamplePlugin)
      assert [%{"slug" => "sample"}] = Registry.list()
    end

    test "returns {:error, :module_not_loaded} for unknown modules" do
      assert {:error, _} = Registry.register(NoSuchPlugin)
    end
  end

  describe "list/0" do
    test "returns metadata + UI block + healthy flag" do
      Registry.register(SamplePlugin)
      [entry] = Registry.list()

      assert entry["slug"] == "sample"
      assert entry["name"] == "Sample plugin"
      assert entry["version"] == "1.2.3"
      assert entry["healthy"] == true
      assert entry["ui"]["title"] == "Sample"
      assert entry["ui"]["view"] == "table"
      assert entry["ui"]["resources"] == ["rows"]
    end

    test "returns [] when nothing is registered" do
      assert [] = Registry.list()
    end
  end

  describe "get/1 + get_resource/2" do
    setup do
      Registry.register(SamplePlugin)
      :ok
    end

    test "get/1 returns one plugin by slug" do
      assert %{"slug" => "sample"} = Registry.get(:sample)
      assert %{"slug" => "sample"} = Registry.get("sample")
      assert is_nil(Registry.get(:none))
    end

    test "get_resource/2 returns the plugin's payload" do
      assert {:ok, [%{"a" => 1}, %{"a" => 2}]} = Registry.get_resource(:sample, :rows)
    end

    test "get_resource/2 returns :unknown_plugin for missing slug" do
      assert {:error, :unknown_plugin} = Registry.get_resource(:nope, :rows)
    end

    test "get_resource/2 surfaces the plugin's :not_found" do
      assert {:error, :not_found} = Registry.get_resource(:sample, :unknown_resource)
    end
  end

  describe "plugins without get_resource/1" do
    test "are listable but resource-less" do
      Registry.register(MetadataOnlyPlugin)
      assert {:error, :not_found} = Registry.get_resource(:only_metadata, :anything)
    end
  end

  describe "unregister/1" do
    test "is idempotent" do
      Registry.register(SamplePlugin)
      assert :ok = Registry.unregister(:sample)
      assert :ok = Registry.unregister(:sample)
      assert [] = Registry.list()
    end
  end
end
