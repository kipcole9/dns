defmodule ExDns.BlackHole.Groups do
  @moduledoc """
  Helpers for the per-client groups table.

  Each group declares a list of CIDRs and the blocklists it
  applies. The plugin's `routes/0` is computed from this
  table — one route per group, with the group's id stuffed
  into the route's `:meta` so `policy_resolve/2` can pick the
  right blocklist subset on a hit.

  Today's mapping is intentionally simple: the route metadata
  carries the group id; the plugin reaches into storage to
  resolve the blocklist subset on each query. A future
  optimisation precomputes one compiled `Set` per group.
  """

  alias ExDns.BlackHole.Storage

  @doc """
  Build the route list the plugin's `routes/0` returns.
  Each enabled group's CIDRs become one route entry.
  """
  @spec routes() :: [ExDns.Plugin.Policy.route()]
  def routes do
    Storage.list_groups()
    |> Enum.filter(fn g -> g["enabled"] == true end)
    |> Enum.flat_map(&group_to_routes/1)
  end

  defp group_to_routes(%{"cidrs" => cidrs}) when is_list(cidrs) do
    parsed = Enum.flat_map(cidrs, &parse_cidr/1)

    if parsed == [] do
      []
    else
      [%{cidrs: parsed, qtypes: :any, priority: 50}]
    end
  end

  defp group_to_routes(_), do: []

  defp parse_cidr(cidr) when is_binary(cidr) do
    case String.split(cidr, "/", parts: 2) do
      [ip_string, prefix_string] ->
        with {prefix, ""} <- Integer.parse(prefix_string),
             {:ok, ip} <-
               :inet.parse_address(String.to_charlist(ip_string)) do
          [{ip, prefix}]
        else
          _ -> []
        end

      [ip_string] ->
        # Bare IP — treat as /32 (or /128 for IPv6).
        case :inet.parse_address(String.to_charlist(ip_string)) do
          {:ok, {_, _, _, _} = ip} -> [{ip, 32}]
          {:ok, {_, _, _, _, _, _, _, _} = ip} -> [{ip, 128}]
          _ -> []
        end
    end
  end

  defp parse_cidr(_), do: []
end
