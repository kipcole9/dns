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

  @doc """
  Add a new record to `apex`. Decodes the JSON rdata via the
  resource module's `decode_rdata/1` (per
  `ExDns.Resource.JSON`) and writes the augmented record set
  back via `Storage.put_zone/2`.

  Triggers an `ExDns.Zone.Snapshot.Writer.request/0` — the
  same hook RFC 2136 UPDATE uses — so on-disk state catches up.

  ### Returns

  * `{:ok, record_json}` — the new record's API JSON
    (including its assigned id).
  * `{:error, :zone_not_loaded}` when the apex is unknown.
  * `{:error, :invalid_type}` when the type isn't recognised.
  * `{:error, reason}` from the resource module's
    `decode_rdata/1` on rdata-shape problems.
  """
  @spec add_record(binary(), map()) :: {:ok, map()} | {:error, term()}
  def add_record(apex, attributes) when is_map(attributes) do
    apex_norm = normalise(apex)

    with {:ok, current} <- dump_zone(apex_norm),
         {:ok, record} <- build_record(attributes) do
      records = current ++ [record]
      Storage.put_zone(apex_norm, records)
      ExDns.Zone.Snapshot.Writer.request()
      {:ok, APIJSON.record(record)}
    end
  end

  @doc """
  Replace one record (identified by its API id). The new
  record's name/ttl/class/rdata come from `attributes`. The id
  itself is recomputed (a successful PATCH always changes
  the id, since it hashes the new content).

  ### Returns

  * `{:ok, new_record_json}`.
  * `{:error, :zone_not_loaded | :record_not_found |
    :invalid_type | reason}`.
  """
  @spec update_record(binary(), binary(), map()) ::
          {:ok, map()} | {:error, term()}
  def update_record(apex, id, attributes) when is_binary(id) and is_map(attributes) do
    apex_norm = normalise(apex)

    with {:ok, current} <- dump_zone(apex_norm),
         {:ok, replaced, kept} <- partition_by_id(current, id),
         _ = replaced,
         {:ok, new_record} <- build_record(attributes) do
      records = kept ++ [new_record]
      Storage.put_zone(apex_norm, records)
      ExDns.Zone.Snapshot.Writer.request()
      {:ok, APIJSON.record(new_record)}
    end
  end

  @doc """
  Delete the record with the given API id from `apex`.

  ### Returns

  * `:ok`.
  * `{:error, :zone_not_loaded | :record_not_found}`.
  """
  @spec delete_record(binary(), binary()) :: :ok | {:error, term()}
  def delete_record(apex, id) when is_binary(id) do
    apex_norm = normalise(apex)

    with {:ok, current} <- dump_zone(apex_norm),
         {:ok, _removed, kept} <- partition_by_id(current, id) do
      Storage.put_zone(apex_norm, kept)
      ExDns.Zone.Snapshot.Writer.request()
      :ok
    end
  end

  @doc """
  Re-read every zone file in `:ex_dns, :zones`, replacing the
  in-memory copy. Returns `{:ok, %{loaded, failed}}`.
  """
  @spec reload_zones() :: {:ok, %{loaded: non_neg_integer(), failed: non_neg_integer()}}
  def reload_zones do
    {loaded, failed} = ExDns.Zone.Reload.reload_all()
    ExDns.Zone.Snapshot.Writer.request()
    {:ok, %{loaded: loaded, failed: failed}}
  end

  defp dump_zone(apex) do
    case Storage.dump_zone(apex) do
      {:ok, records} -> {:ok, records}
      {:error, :not_loaded} -> {:error, :zone_not_loaded}
    end
  end

  # Build a fully-populated resource struct from a JSON-shaped
  # `attributes` map (`%{"name" => …, "type" => …, "ttl" => …,
  # "class" => …, "rdata" => %{…}}`).
  defp build_record(%{"type" => type} = attributes) when is_binary(type) do
    case resource_module_for(type) do
      nil ->
        {:error, :invalid_type}

      module ->
        rdata = Map.get(attributes, "rdata", %{})

        cond do
          not function_exported?(module, :decode_rdata, 1) ->
            {:error, :type_not_writable}

          true ->
            case module.decode_rdata(rdata) do
              {:ok, partial} -> {:ok, populate_envelope(partial, attributes)}
              {:error, _} = err -> err
            end
        end
    end
  end

  defp build_record(_), do: {:error, :missing_type}

  defp populate_envelope(struct, attributes) do
    %{
      struct
      | name: Map.get(attributes, "name"),
        ttl: Map.get(attributes, "ttl", 60),
        class: parse_class(Map.get(attributes, "class", "IN"))
    }
  end

  defp parse_class("IN"), do: :in
  defp parse_class("CH"), do: :ch
  defp parse_class("HS"), do: :hs
  defp parse_class(other) when is_atom(other), do: other
  defp parse_class(_), do: :in

  defp resource_module_for(type) when is_binary(type) do
    upcased = String.upcase(type)
    candidate = Module.concat([ExDns.Resource, upcased])

    if Code.ensure_loaded?(candidate) and function_exported?(candidate, :__struct__, 0) do
      candidate
    end
  end

  defp partition_by_id(records, id) do
    matched = Enum.find(records, fn r -> APIJSON.record_id(r) == id end)

    if matched do
      kept = Enum.reject(records, fn r -> APIJSON.record_id(r) == id end)
      {:ok, matched, kept}
    else
      {:error, :record_not_found}
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

  @doc """
  Trigger an immediate refresh on the secondary state machine
  for `apex`. Returns `:ok` or `{:error, :no_secondary_for_zone}`.
  """
  @spec refresh_secondary(binary()) :: :ok | {:error, :no_secondary_for_zone}
  def refresh_secondary(apex) when is_binary(apex) do
    ExDns.Zone.Secondary.notify(apex)
  end

  @doc """
  Advance a DNSSEC key through its rollover lifecycle.
  """
  @spec advance_rollover(binary(), atom(), atom(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def advance_rollover(zone, role, phase, options \\ [])

  def advance_rollover(zone, :zsk, :prepare, options) do
    wrap_rollover(ExDns.DNSSEC.Rollover.prepare_zsk_rollover(zone, options))
  end

  def advance_rollover(zone, :zsk, :complete, options) do
    new_key_tag = Keyword.fetch!(options, :new_key_tag)
    wrap_rollover(ExDns.DNSSEC.Rollover.complete_zsk_rollover(zone, new_key_tag))
  end

  def advance_rollover(zone, :zsk, :purge, _options) do
    wrap_rollover(ExDns.DNSSEC.Rollover.purge_retired_keys(zone))
  end

  def advance_rollover(zone, :ksk, :prepare, options) do
    wrap_rollover(ExDns.DNSSEC.Rollover.prepare_ksk_rollover(zone, options))
  end

  def advance_rollover(zone, :ksk, :complete, options) do
    new_key_tag = Keyword.fetch!(options, :new_key_tag)
    wrap_rollover(ExDns.DNSSEC.Rollover.complete_ksk_rollover(zone, new_key_tag))
  end

  def advance_rollover(_zone, _role, _phase, _options), do: {:error, :unknown_phase}

  defp wrap_rollover({:ok, info}), do: {:ok, format_rollover(info)}
  defp wrap_rollover({:error, _} = err), do: err
  defp wrap_rollover(other), do: {:ok, format_rollover_other(other)}

  defp format_rollover(info) when is_map(info) do
    Enum.into(info, %{}, fn {k, v} -> {to_key(k), to_jsonable(v)} end)
  end

  defp format_rollover(info), do: %{"result" => to_jsonable(info)}

  defp format_rollover_other(other), do: %{"result" => to_jsonable(other)}

  defp to_key(k) when is_atom(k), do: Atom.to_string(k)
  defp to_key(k), do: to_string(k)

  defp to_jsonable(v) when is_atom(v) and not is_boolean(v) and not is_nil(v),
    do: Atom.to_string(v)

  defp to_jsonable(v) when is_tuple(v), do: inspect(v)
  defp to_jsonable(v), do: v

  @doc """
  DNSSEC key inventory across every loaded zone. Calls
  `ExDns.DNSSEC.KeyStore.signing_keys/1` per zone and
  flattens.
  """
  @spec keys() :: [map()]
  def keys do
    if Code.ensure_loaded?(ExDns.DNSSEC.KeyStore) and
         function_exported?(ExDns.DNSSEC.KeyStore, :signing_keys, 1) do
      Storage.zones()
      |> Enum.flat_map(fn apex ->
        apex
        |> ExDns.DNSSEC.KeyStore.signing_keys()
        |> Enum.map(fn key -> Map.put(key, :zone, apex) end)
      end)
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

  @doc "One plugin's metadata + UI block, or `nil`."
  @spec plugin(binary()) :: map() | nil
  def plugin(slug) do
    if Code.ensure_loaded?(ExDns.Plugin.Registry) do
      ExDns.Plugin.Registry.get(slug)
    end
  end

  @doc """
  Fetch a plugin's named resource. Returns `{:ok, payload}`
  / `{:error, :unknown_plugin | :not_found | reason}`.
  """
  @spec plugin_resource(binary(), binary()) :: {:ok, term()} | {:error, term()}
  def plugin_resource(slug, resource) when is_binary(slug) and is_binary(resource) do
    if Code.ensure_loaded?(ExDns.Plugin.Registry) do
      ExDns.Plugin.Registry.get_resource(slug, resource)
    else
      {:error, :unknown_plugin}
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
    ExDns.API.MetricsCounters.snapshot(window_secs)
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
end
