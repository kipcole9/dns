defmodule ExDns.Plugin.Registry do
  @moduledoc """
  In-process registry of installed `ExDns.Plugin` modules.

  ## Two stores in `:persistent_term`

  * `{__MODULE__, :registry}` — `slug => entry` map of every
    registered plugin (metadata + UI block + routes). Reads
    here are infrequent (admin API, list pages).

  * `{__MODULE__, :route_index}` — a flat list of route
    records derived from every plugin's `routes/0`. Walked on
    every query that reaches the plugin pipeline, so updates
    rebuild the list in one shot and atomically swap the
    persistent-term reference.

  ## Public API

  * `register/1` — register a plugin module (calls its
    `routes/0` if it implements `ExDns.Plugin.Policy`).
  * `unregister/1` — remove by slug.
  * `list/0` / `get/1` — registered plugins' JSON-shaped
    metadata.
  * `get_resource/2` — call `get_resource/1` on the plugin
    and return `{:ok, payload}` / `{:error, reason}`.
  * `update_routes/2` — replace one plugin's routes at
    runtime (BlackHole calls this when a group's CIDRs
    change).
  * `match/1` — given a request, return at most one
    `{plugin_module, route}` pair to dispatch to, or `:none`.
  """

  use Bitwise

  alias ExDns.Plugin.Policy
  alias ExDns.Plugin.Registry.Backend

  @doc "Register `plugin_module`. Returns `:ok` or `{:error, reason}`."
  @spec register(module()) :: :ok | {:error, term()}
  def register(plugin_module) when is_atom(plugin_module) do
    with true <- Code.ensure_loaded?(plugin_module) || {:error, :module_not_loaded},
         true <- function_exported?(plugin_module, :metadata, 0) || {:error, :no_metadata},
         metadata <- plugin_module.metadata(),
         slug when is_atom(slug) <- Map.fetch!(metadata, :slug) do
      routes = collect_routes(plugin_module)

      entry = %{
        module: plugin_module,
        metadata: metadata,
        routes: routes,
        registration_index: next_index(),
        healthy: true
      }

      put(slug, entry)
      rebuild_route_index()
      :ok
    else
      {:error, _} = err -> err
      _ -> {:error, :invalid_plugin}
    end
  end

  @doc "Remove a plugin by slug. Idempotent."
  @spec unregister(atom()) :: :ok
  def unregister(slug) when is_atom(slug) do
    state() |> Map.delete(slug) |> put_state()
    rebuild_route_index()
    :ok
  end

  @doc """
  Replace `slug`'s routes at runtime. Atomically rebuilds the
  route index. Used by plugins whose CIDRs change at runtime
  (e.g. BlackHole's group editor).
  """
  @spec update_routes(atom() | binary(), [Policy.route()]) :: :ok | {:error, :unknown_plugin}
  def update_routes(slug, new_routes) when is_list(new_routes) do
    norm = normalise(slug)

    case Map.get(state(), norm) do
      nil ->
        {:error, :unknown_plugin}

      entry ->
        normalised = Enum.map(new_routes, &normalise_route/1)
        put(norm, %{entry | routes: normalised})
        rebuild_route_index()
        :ok
    end
  end

  @doc "Return every registered plugin's metadata + healthy flag."
  @spec list() :: [map()]
  def list do
    state()
    |> Enum.map(fn {_slug, entry} -> serialise(entry) end)
    |> Enum.sort_by(& &1["slug"])
  end

  @doc "Return one plugin by slug, or nil."
  @spec get(atom() | binary()) :: map() | nil
  def get(slug) do
    case Map.get(state(), normalise(slug)) do
      nil -> nil
      entry -> serialise(entry)
    end
  end

  @doc """
  Fetch the JSON payload for `resource` from the plugin
  identified by `slug`. The payload is whatever the plugin's
  `get_resource/1` returns.
  """
  @spec get_resource(atom() | binary(), atom() | binary()) ::
          {:ok, term()} | {:error, :unknown_plugin | :not_found | term()}
  def get_resource(slug, resource) do
    case Map.get(state(), normalise(slug)) do
      nil ->
        {:error, :unknown_plugin}

      %{module: module} ->
        if function_exported?(module, :get_resource, 1) do
          module.get_resource(normalise(resource))
        else
          {:error, :not_found}
        end
    end
  end

  @doc """
  Look up the best route for `request`.

  Walks the route index, filters by source-IP CIDR + qtype +
  qname-suffix, and returns the most-specific match (longest
  prefix → highest priority → earliest registration). Returns
  `:none` when nothing matches; the caller falls through to
  the underlying resolver.

  Pass-through is the *floor* — `:none` MUST mean the request
  flows unmodified.
  """
  @spec match(ExDns.Request.t()) ::
          {:ok, module(), Policy.route()} | :none
  def match(%ExDns.Request{} = request) do
    case route_index() do
      [] -> :none
      routes -> pick_best(request, routes)
    end
  end

  @doc """
  Dispatch a mutating action to the plugin identified by
  `slug`. Returns the plugin's `handle_action/2` return value
  unmodified, or `{:error, :unknown_plugin | :no_action}`.
  """
  @spec dispatch_action(atom() | binary(), binary(), map()) ::
          {:ok, term()} | {:error, term()}
  def dispatch_action(slug, name, params) when is_binary(name) and is_map(params) do
    case Map.get(state(), normalise(slug)) do
      nil ->
        {:error, :unknown_plugin}

      %{module: module} ->
        if function_exported?(module, :handle_action, 2) do
          module.handle_action(name, params)
        else
          {:error, :no_action}
        end
    end
  end

  @doc "Reset the registry. Test helper."
  @spec clear() :: :ok
  def clear do
    Backend.configured().clear()
  end

  # ----- route-index internals --------------------------------------

  defp collect_routes(plugin_module) do
    cond do
      not function_exported?(plugin_module, :routes, 0) ->
        []

      true ->
        plugin_module.routes()
        |> Enum.map(&normalise_route/1)
    end
  end

  defp normalise_route(%{} = route) do
    %{
      cidrs: Map.fetch!(route, :cidrs),
      qtypes: Map.get(route, :qtypes, :any),
      qname_suffix: Map.get(route, :qname_suffix),
      priority: Map.get(route, :priority, 50)
    }
  end

  defp rebuild_route_index do
    flat =
      state()
      |> Enum.flat_map(fn {slug, %{module: module, routes: routes, registration_index: rix}} ->
        Enum.map(routes, fn route -> {slug, module, rix, route} end)
      end)

    Backend.configured().put_route_index(flat)
  end

  defp route_index, do: Backend.configured().route_index()

  defp pick_best(request, routes) do
    qname = qname_from(request)
    qtype = qtype_from(request)
    source_ip = request.source_ip

    routes
    |> Enum.flat_map(fn {slug, module, rix, route} ->
      case best_cidr_match(source_ip, route.cidrs) do
        nil ->
          []

        prefix_len ->
          if qtype_allowed?(route.qtypes, qtype) and
               qname_allowed?(route.qname_suffix, qname) do
            [{prefix_len, route.priority, rix, slug, module, route}]
          else
            []
          end
      end
    end)
    |> case do
      [] ->
        :none

      candidates ->
        # longest prefix → highest priority → earliest registration
        {_, _, _, _slug, module, route} =
          Enum.max_by(candidates, fn {prefix_len, priority, rix, _, _, _} ->
            {prefix_len, priority, -rix}
          end)

        {:ok, module, route}
    end
  end

  defp qname_from(%ExDns.Request{message: %{question: %{host: host}}}) when is_binary(host) do
    host |> String.trim_trailing(".") |> String.downcase(:ascii)
  end

  defp qname_from(_), do: ""

  defp qtype_from(%ExDns.Request{message: %{question: %{type: type}}}), do: type
  defp qtype_from(_), do: nil

  defp qtype_allowed?(:any, _qtype), do: true
  defp qtype_allowed?(qtypes, qtype) when is_list(qtypes), do: qtype in qtypes
  defp qtype_allowed?(_, _), do: false

  defp qname_allowed?(nil, _qname), do: true
  defp qname_allowed?("", _qname), do: true

  defp qname_allowed?(suffix, qname) when is_binary(suffix) and is_binary(qname) do
    suffix_norm = suffix |> String.trim_trailing(".") |> String.downcase(:ascii)
    qname == suffix_norm or String.ends_with?(qname, "." <> suffix_norm)
  end

  defp best_cidr_match(nil, _), do: nil

  defp best_cidr_match(source_ip, cidrs) do
    cidrs
    |> Enum.flat_map(fn {ip, prefix_len} ->
      if cidr_contains?(ip, prefix_len, source_ip), do: [prefix_len], else: []
    end)
    |> case do
      [] -> nil
      lens -> Enum.max(lens)
    end
  end

  defp cidr_contains?({a, b, c, d}, prefix_len, {sa, sb, sc, sd})
       when prefix_len in 0..32 do
    cidr_int = ipv4_to_int(a, b, c, d)
    src_int = ipv4_to_int(sa, sb, sc, sd)
    mask = if prefix_len == 0, do: 0, else: 0xFFFFFFFF <<< (32 - prefix_len) &&& 0xFFFFFFFF
    Bitwise.band(cidr_int, mask) == Bitwise.band(src_int, mask)
  end

  defp cidr_contains?({_, _, _, _, _, _, _, _} = cidr_ip, prefix_len, {_, _, _, _, _, _, _, _} = src_ip)
       when prefix_len in 0..128 do
    cidr_int = ipv6_to_int(cidr_ip)
    src_int = ipv6_to_int(src_ip)
    bits = 128 - prefix_len
    mask = if prefix_len == 0, do: 0, else: Bitwise.bsl(Bitwise.bsr(-1, 0), 0) |> ipv6_mask(bits)
    Bitwise.band(cidr_int, mask) == Bitwise.band(src_int, mask)
  end

  defp cidr_contains?(_, _, _), do: false

  defp ipv4_to_int(a, b, c, d), do: a <<< 24 ||| b <<< 16 ||| c <<< 8 ||| d

  defp ipv6_to_int({a, b, c, d, e, f, g, h}) do
    <<int::size(128)>> =
      <<a::size(16), b::size(16), c::size(16), d::size(16), e::size(16), f::size(16),
        g::size(16), h::size(16)>>

    int
  end

  # 128-bit mask with `bits` zero bits at the bottom.
  defp ipv6_mask(_, bits) when bits >= 128, do: 0
  defp ipv6_mask(_, bits), do: Bitwise.bsl(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, bits) &&& 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

  # ----- registry storage -------------------------------------------

  defp put(slug, entry) do
    state()
    |> Map.put(slug, entry)
    |> put_state()
  end

  defp put_state(state), do: Backend.configured().put_registry_state(state)
  defp state, do: Backend.configured().registry_state()

  defp next_index do
    state() |> map_size()
  end

  defp serialise(%{metadata: metadata, healthy: healthy}) do
    %{
      "slug" => to_string(metadata.slug),
      "name" => Map.get(metadata, :name, ""),
      "version" => Map.get(metadata, :version, "0.0.0"),
      "node" => to_string(Node.self()),
      "enabled" => true,
      "healthy" => healthy,
      "ui" => format_ui(Map.get(metadata, :ui))
    }
  end

  defp format_ui(nil), do: nil

  defp format_ui(%{} = ui) do
    %{
      "title" => Map.get(ui, :title),
      "view" => ui |> Map.get(:view, :table) |> to_string(),
      "resources" => ui |> Map.get(:resources, []) |> Enum.map(&to_string/1)
    }
  end

  defp normalise(value) when is_atom(value), do: value |> Atom.to_string() |> normalise()
  defp normalise(value) when is_binary(value), do: String.to_atom(value)
end
