defmodule ExDns.Resolver.PerZoneRouter do
  @moduledoc """
  Suffix-based query router for per-zone forwarding.

  Operators register zones → upstream lists; this module returns
  the best (longest-suffix) match for a given qname so the
  surrounding resolver can decide between forwarding to that
  upstream and falling through to the default resolver.

  ## Configuration

      config :ex_dns, :per_zone_forwarders, %{
        "internal.example" => [{{10, 0, 0, 5}, 53}],
        "ad.example"       => [{{10, 0, 0, 6}, 53}]
      }

  Both map and keyword-list shapes are accepted — the keys are
  zone names (case-insensitive, trailing-dot-stripped); the
  values are lists of `{ip_address, port}`.

  ## Match precedence

  Longest matching suffix wins:

      route("mail.internal.example") → "internal.example"
      route("internal.example")      → "internal.example"
      route("ad.example")            → "ad.example"
      route("other.example")         → :passthru
  """

  @doc """
  Returns the upstreams configured for the longest-matching
  zone suffix of `qname`, or `:passthru` when no zone matches.

  ### Arguments

  * `qname` is the lower-cased, trailing-dot-stripped query
    name.

  ### Options

  * `:routes` — a map or keyword list overriding the
    application-env routes (used by tests).

  ### Returns

  * `{:forward, zone, [{ip, port}]}` — `zone` is the matched
    zone name (lower-cased), `[...]` is its upstream list.
  * `:passthru` — no zone in the table matched.

  ### Examples

      iex> ExDns.Resolver.PerZoneRouter.route("nope.test", routes: %{})
      :passthru

      iex> ExDns.Resolver.PerZoneRouter.route("mail.internal.example",
      ...>   routes: %{"internal.example" => [{{10, 0, 0, 5}, 53}]})
      {:forward, "internal.example", [{{10, 0, 0, 5}, 53}]}

  """
  @spec route(binary(), keyword()) ::
          {:forward, binary(), [{:inet.ip_address(), :inet.port_number()}]}
          | :passthru
  def route(qname, options \\ []) when is_binary(qname) do
    routes = Keyword.get_lazy(options, :routes, &configured_routes/0)
    norm = normalize(qname)

    routes
    |> normalize_routes()
    |> Enum.filter(fn {zone, _ups} -> matches?(norm, zone) end)
    |> Enum.max_by(fn {zone, _ups} -> byte_size(zone) end, fn -> nil end)
    |> case do
      nil -> :passthru
      {zone, upstreams} -> {:forward, zone, upstreams}
    end
  end

  @doc """
  Returns the configured route table from application env, in
  the canonical map shape with normalised keys.

  ### Returns

  * A map of `zone => [upstream]`. Empty when nothing is
    configured.

  ### Examples

      iex> Application.delete_env(:ex_dns, :per_zone_forwarders)
      iex> ExDns.Resolver.PerZoneRouter.configured_routes()
      %{}

  """
  @spec configured_routes() :: %{optional(binary()) => list()}
  def configured_routes do
    :ex_dns
    |> Application.get_env(:per_zone_forwarders, %{})
    |> normalize_routes()
    |> Map.new()
  end

  defp normalize_routes(routes) when is_list(routes) do
    Enum.map(routes, fn {zone, ups} -> {normalize(zone), ups} end)
  end

  defp normalize_routes(routes) when is_map(routes) do
    Enum.map(routes, fn {zone, ups} -> {normalize(to_string(zone)), ups} end)
  end

  defp normalize(zone) when is_atom(zone), do: zone |> Atom.to_string() |> normalize()

  defp normalize(zone) when is_binary(zone) do
    zone
    |> String.trim_trailing(".")
    |> String.downcase(:ascii)
  end

  defp matches?(qname, zone) when zone == "", do: is_binary(qname)

  defp matches?(qname, zone) do
    qname == zone or String.ends_with?(qname, "." <> zone)
  end
end
