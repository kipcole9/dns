defmodule ExDns.API.Resources do
  @moduledoc """
  Data layer behind the `/api/v1/*` routes — exposes server
  state as JSON-friendly maps.

  Split out from `ExDns.API.Router` so the same data can be
  driven from a `mix` task, a test, or a CLI tool without
  going through HTTP.
  """

  alias ExDns.API.JSON, as: APIJSON
  alias ExDns.Resource.SOA
  alias ExDns.Storage

  @doc """
  Server identity, version, listener bindings, cluster nodes.
  """
  @spec server() :: map()
  def server do
    %{
      "identity" => identity(),
      "version" => version(),
      "listeners" => listeners(),
      "cluster" => cluster()
    }
  end

  @doc "List of zones with apex, serial, kind."
  @spec zones() :: [map()]
  def zones do
    Storage.zones()
    |> Enum.map(&zone_summary/1)
  end

  @doc """
  One zone's metadata + per-type record counts. Returns `nil`
  when the apex isn't loaded.
  """
  @spec zone(binary()) :: map() | nil
  def zone(apex) do
    apex_norm = normalise(apex)

    if apex_norm in zones_normalised() do
      summary = zone_summary(apex_norm)
      Map.put(summary, "counts", record_counts(apex_norm))
    else
      nil
    end
  end

  @doc """
  Paginated record listing for a zone with optional type and
  name-substring filters.
  """
  @spec records(binary(), %{
          optional(:type) => binary() | nil,
          optional(:name) => binary() | nil,
          optional(:limit) => pos_integer(),
          optional(:offset) => non_neg_integer()
        }) :: %{records: [map()], total: non_neg_integer()}
  def records(apex, options) when is_map(options) do
    apex_norm = normalise(apex)

    case Storage.dump_zone(apex_norm) do
      {:ok, all_records} ->
        filtered =
          all_records
          |> filter_by_type(options[:type])
          |> filter_by_name(options[:name])

        page =
          filtered
          |> Enum.drop(options[:offset] || 0)
          |> Enum.take(options[:limit] || 200)
          |> Enum.map(&APIJSON.record/1)

        %{records: page, total: length(filtered)}

      _ ->
        %{records: [], total: 0}
    end
  end

  @doc "Snapshot for one secondary zone, or `nil` when none is configured."
  @spec secondary(binary()) :: map() | nil
  def secondary(apex) do
    case ExDns.Zone.Secondary.snapshot(apex) do
      nil ->
        nil

      {state, data} ->
        %{
          "apex" => apex,
          "state" => Atom.to_string(state),
          "serial" => serial_or_nil(data.soa),
          "last_success_unix" => last_success_unix(data),
          "tsig_key" => data.tsig_key
        }
    end
  end

  @doc "DNSSEC key inventory across all zones."
  @spec keys() :: [map()]
  def keys do
    if Code.ensure_loaded?(ExDns.DNSSEC.KeyStore) and
         function_exported?(ExDns.DNSSEC.KeyStore, :all_signing_keys, 0) do
      ExDns.DNSSEC.KeyStore.all_signing_keys()
      |> Enum.map(&format_key/1)
    else
      []
    end
  end

  @doc "Plugin registry — slug, node, version, healthy?, UI metadata."
  @spec plugins() :: [map()]
  def plugins do
    if Code.ensure_loaded?(ExDns.Plugin.Registry) and
         function_exported?(ExDns.Plugin.Registry, :list, 0) do
      ExDns.Plugin.Registry.list()
    else
      []
    end
  end

  @doc """
  Time-bucketed metrics summary (queries by qtype, RRL drops,
  cache hit/miss, DNSSEC outcomes) over the last `window_secs`.

  The values are the in-process counters' current totals; the
  caller is the one with sub-window granularity if they hit the
  endpoint repeatedly.
  """
  @spec metrics_summary(pos_integer()) :: map()
  def metrics_summary(window_secs) do
    %{
      "window_seconds" => window_secs,
      "queries" => metrics_value(:queries) || %{},
      "rrl_drops" => metrics_value(:rrl_drops) || 0,
      "cache_hits" => metrics_value(:cache_hits) || %{"hit" => 0, "miss" => 0},
      "dnssec" => metrics_value(:dnssec) || %{}
    }
  end

  # ----- helpers ----------------------------------------------------

  defp identity do
    case Application.get_env(:ex_dns, :nsid, []) do
      list when is_list(list) ->
        case Keyword.get(list, :identifier) do
          nil ->
            {:ok, host} = :inet.gethostname()
            to_string(host)

          id when is_binary(id) ->
            id
        end

      _ ->
        {:ok, host} = :inet.gethostname()
        to_string(host)
    end
  end

  defp version do
    case :application.get_key(:ex_dns, :vsn) do
      {:ok, vsn} -> to_string(vsn)
      _ -> "unknown"
    end
  end

  defp listeners do
    [
      udp_listener(),
      tcp_listener(),
      dot_listener(),
      doh_listener()
    ]
    |> Enum.reject(&is_nil/1)
  end

  defp udp_listener do
    %{"transport" => "udp", "address" => "127.0.0.1", "port" => ExDns.listener_port()}
  end

  defp tcp_listener do
    %{"transport" => "tcp", "address" => "127.0.0.1", "port" => ExDns.listener_port()}
  end

  defp dot_listener do
    case Application.get_env(:ex_dns, :dot) do
      list when is_list(list) ->
        if Keyword.get(list, :enabled, false) do
          %{
            "transport" => "dot",
            "address" => "127.0.0.1",
            "port" => Keyword.get(list, :port, 853)
          }
        end

      _ ->
        nil
    end
  end

  defp doh_listener do
    case Application.get_env(:ex_dns, :doh) do
      list when is_list(list) ->
        if Keyword.get(list, :enabled, false) do
          %{
            "transport" => "doh",
            "address" => "127.0.0.1",
            "port" => Keyword.get(list, :port, 8443)
          }
        end

      _ ->
        nil
    end
  end

  defp cluster do
    nodes = [Node.self() | Node.list()] |> Enum.map(&to_string/1)
    %{"nodes" => nodes, "master" => master()}
  end

  defp master do
    case :global.whereis_name(:ex_dns_update_master) do
      :undefined -> nil
      pid -> pid |> node() |> to_string()
    end
  end

  defp zone_summary(apex) do
    %{
      "apex" => apex,
      "serial" => serial_for(apex),
      "kind" => kind_for(apex),
      "source" => source_for(apex)
    }
  end

  defp serial_for(apex) do
    case Storage.lookup(apex, :soa) do
      {:ok, _, [%SOA{serial: serial} | _]} -> serial
      _ -> nil
    end
  end

  defp kind_for(apex) do
    cond do
      ExDns.Zone.Secondary.snapshot(apex) != nil -> "secondary"
      catalog_apex?(apex) -> "catalog"
      true -> "primary"
    end
  end

  defp catalog_apex?(apex) do
    case Application.get_env(:ex_dns, :catalogs) do
      list when is_list(list) ->
        Enum.any?(list, fn entry ->
          entry |> Map.get(:catalog_apex, "") |> normalise() == normalise(apex)
        end)

      _ ->
        false
    end
  end

  defp source_for(_apex), do: nil

  defp record_counts(apex) do
    case Storage.dump_zone(apex) do
      {:ok, records} ->
        Enum.reduce(records, %{}, fn record, acc ->
          type = record.__struct__ |> Module.split() |> List.last() |> String.upcase()
          Map.update(acc, type, 1, &(&1 + 1))
        end)

      _ ->
        %{}
    end
  end

  defp filter_by_type(records, nil), do: records

  defp filter_by_type(records, type) when is_binary(type) do
    upper = String.upcase(type)

    Enum.filter(records, fn r ->
      (r.__struct__ |> Module.split() |> List.last() |> String.upcase()) == upper
    end)
  end

  defp filter_by_name(records, nil), do: records

  defp filter_by_name(records, substring) when is_binary(substring) do
    needle = String.downcase(substring, :ascii)

    Enum.filter(records, fn %{name: name} when is_binary(name) ->
      String.contains?(String.downcase(name, :ascii), needle)
    end)
  end

  defp zones_normalised do
    Enum.map(Storage.zones(), &normalise/1)
  end

  defp normalise(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end

  defp normalise(name) when is_atom(name), do: name |> Atom.to_string() |> normalise()

  defp serial_or_nil(%SOA{serial: serial}), do: serial
  defp serial_or_nil(_), do: nil

  defp last_success_unix(%{last_success: nil}), do: nil

  defp last_success_unix(%{last_success: monotonic}) when is_integer(monotonic) do
    now_mono = System.monotonic_time(:second)
    now_wall = System.os_time(:second)
    now_wall - (now_mono - monotonic)
  end

  defp last_success_unix(_), do: nil

  defp format_key(key) do
    %{
      "zone" => Map.get(key, :zone, ""),
      "role" => key |> Map.get(:role, :zsk) |> to_string(),
      "algorithm" => Map.get(key, :algorithm, 0),
      "key_tag" => Map.get(key, :key_tag, 0),
      "state" => key |> Map.get(:state, :active) |> to_string()
    }
  end

  defp metrics_value(_), do: nil
end
