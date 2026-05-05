defmodule ExDns.MDNS.Plugin do
  @moduledoc """
  Surfaces the mDNS visualizer through the plugin registry so
  the Web UI can render it as a tab without depending on the
  visualizer's standalone HTTP server.

  The data comes from `ExDns.MDNS.Visualizer.Discoverer`, which
  was already running as the source of truth for the legacy
  `Standalone` visualizer. The plugin doesn't duplicate any
  state — it just translates the discoverer's snapshot into
  the JSON shape the UI's generic `:table` view expects.

  ## Resource shapes

  * `:services` — list of service rows:
    `%{type, instance, target, port, addresses, txt}`.
  * `:summary` — one-shot aggregate:
    `%{cycles, last_refresh, types, total_instances}`.
  """

  @behaviour ExDns.Plugin

  alias ExDns.MDNS.Visualizer.Discoverer

  @impl true
  def metadata do
    %{
      slug: :mdns,
      name: "mDNS",
      version: "0.1.0",
      ui: %{
        title: "mDNS",
        view: :table,
        resources: [:services, :summary]
      }
    }
  end

  @impl true
  def get_resource(:services) do
    ensure_discoverer_running()
    {:ok, services()}
  end

  def get_resource(:summary) do
    ensure_discoverer_running()
    {:ok, summary()}
  end

  def get_resource(_), do: {:error, :not_found}

  # Start a single discoverer on first use so the plugin works
  # whether or not the operator wired one explicitly.
  defp ensure_discoverer_running do
    case Process.whereis(Discoverer) do
      nil ->
        case Discoverer.start_link([]) do
          {:ok, _} -> :ok
          {:error, {:already_started, _}} -> :ok
          _ -> :ok
        end

      _ ->
        :ok
    end
  end

  defp services do
    snapshot = Discoverer.snapshot()

    snapshot
    |> Map.get(:services, %{})
    |> Enum.flat_map(fn {type, instances} ->
      Enum.map(instances, fn {instance, info} ->
        %{
          "type" => type,
          "instance" => instance,
          "target" => target_for(info),
          "port" => port_for(info),
          "addresses" => addresses_for(info),
          "txt" => txt_for(info)
        }
      end)
    end)
    |> Enum.sort_by(fn row -> {row["type"], row["instance"]} end)
  end

  defp summary do
    snapshot = Discoverer.snapshot()

    %{
      "cycles" => Map.get(snapshot, :cycles, 0),
      "last_refresh" => format_refresh(Map.get(snapshot, :last_refresh)),
      "types" => Map.get(snapshot, :types, []),
      "total_instances" =>
        snapshot
        |> Map.get(:services, %{})
        |> Enum.reduce(0, fn {_, instances}, acc -> acc + map_size(instances) end)
    }
  end

  defp target_for(%{srv: %{target: target}}), do: trim_dot(target)
  defp target_for(_), do: nil

  defp port_for(%{srv: %{port: port}}), do: port
  defp port_for(_), do: nil

  defp addresses_for(%{addresses: addresses}) when is_list(addresses) do
    Enum.map(addresses, &format_addr/1)
  end

  defp addresses_for(_), do: []

  defp format_addr({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"

  defp format_addr({_, _, _, _, _, _, _, _} = ipv6) do
    ipv6 |> :inet.ntoa() |> to_string()
  end

  defp format_addr(other), do: inspect(other)

  defp txt_for(%{txt: %{strings: strings}}) when is_list(strings), do: strings
  defp txt_for(_), do: []

  defp trim_dot(nil), do: nil
  defp trim_dot(s) when is_binary(s), do: String.trim_trailing(s, ".")

  defp format_refresh(nil), do: nil
  defp format_refresh(%DateTime{} = dt), do: DateTime.to_iso8601(dt)
  defp format_refresh(other), do: inspect(other)
end
