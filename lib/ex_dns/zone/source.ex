defmodule ExDns.Zone.Source do
  @moduledoc """
  Resolve the configured `:zones` list to a flat list of zone
  files, with `include`-style glob expansion (BIND-equivalent).

  ## Why

  Production deployments split their zone config across many
  files (one per zone, or one per customer / per VLAN), the
  same way BIND operators wrap zones in `include
  "/etc/bind/zones.d/*.conf"`. ExDns supports the same shape
  via glob expansion of any `:zones` entry containing `*`,
  `?`, or `[...]`:

      config :ex_dns,
        zones: [
          "/etc/exdns/zones/example.com.zone",
          "/etc/exdns/zones.d/*.zone",
          "/etc/exdns/customers/*/*.zone"
        ]

  At load time the wildcard entries are expanded via
  `Path.wildcard/1`, deduplicated, and returned in a stable
  sort order so reloads produce the same logical zone set
  whether files were added through directory creation or
  edits.

  ## Why not real `include`?

  BIND's `include` directive lives inside `named.conf`. Our
  config is `runtime.exs`, evaluated as Elixir — operators can
  literally use `Path.wildcard/1` inline if they prefer. The
  glob-in-`:zones` form is the equivalent muscle memory in
  declarative config.
  """

  @doc """
  Expand the configured `:zones` list to a flat list of paths.

  ### Arguments

  * `entries` — the raw `:zones` config value (list of binary
    paths, possibly containing wildcards).

  ### Returns

  * Flat, deduplicated, sorted list of binary file paths.
    Wildcards that match nothing produce zero entries — not an
    error.

  ### Examples

      iex> ExDns.Zone.Source.expand([])
      []

      iex> ExDns.Zone.Source.expand(["/path/to/literal.zone"])
      ["/path/to/literal.zone"]

  """
  @spec expand([Path.t()]) :: [Path.t()]
  def expand(entries) when is_list(entries) do
    entries
    |> Enum.flat_map(&expand_one/1)
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp expand_one(path) when is_binary(path) do
    if wildcard?(path) do
      Path.wildcard(path)
    else
      [path]
    end
  end

  defp expand_one(_), do: []

  defp wildcard?(path) do
    String.contains?(path, "*") or
      String.contains?(path, "?") or
      String.contains?(path, "[")
  end
end
