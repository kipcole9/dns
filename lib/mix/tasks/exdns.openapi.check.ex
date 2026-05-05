defmodule Mix.Tasks.Exdns.Openapi.Check do
  @shortdoc "Verify the API router and the OpenAPI spec stay in sync."

  @moduledoc """
  Walks the routes registered on `ExDns.API.Router` and the
  paths declared in `priv/openapi/v1.yaml`, then reports any
  drift in either direction:

  * **In the router but not the spec** — undocumented routes.
  * **In the spec but not the router** — promised routes that
    aren't implemented.

  ## Usage

      mix exdns.openapi.check

  Exit status `0` on a clean check, non-zero when any drift
  is reported.

  ## Notes

  This task does NOT validate JSON schemas — only path +
  method coverage. Schema validation belongs in unit tests
  on the resource modules' `encode_rdata/1` callbacks.
  """

  use Mix.Task

  @impl Mix.Task
  def run(_argv) do
    Mix.Task.run("loadpaths")

    spec_paths = parse_spec_paths(spec_path())
    router_paths = collect_router_paths()

    missing_in_spec = MapSet.difference(router_paths, spec_paths)
    missing_in_router = MapSet.difference(spec_paths, router_paths)

    if MapSet.size(missing_in_spec) == 0 and MapSet.size(missing_in_router) == 0 do
      Mix.shell().info("OpenAPI ↔ router: clean.")
      :ok
    else
      report("Routes in router but not in spec:", missing_in_spec)
      report("Routes in spec but not in router:", missing_in_router)
      Mix.raise("OpenAPI drift detected.")
    end
  end

  defp spec_path do
    Application.app_dir(:ex_dns, ["priv", "openapi", "v1.yaml"])
    |> case do
      path ->
        if File.exists?(path) do
          path
        else
          Path.join([File.cwd!(), "priv", "openapi", "v1.yaml"])
        end
    end
  end

  # Tiny YAML-subset reader: we only need the `paths:` keys +
  # which HTTP methods each declares. The OpenAPI doc we ship
  # uses a fixed shape (paths/<path>/<method>), no anchors, no
  # multi-line strings in the keys we care about. Avoids pulling
  # in a YAML dep just for this lint.
  defp parse_spec_paths(path) do
    contents = File.read!(path)
    lines = String.split(contents, "\n")

    {paths, _state} =
      Enum.reduce(lines, {MapSet.new(), :outside}, fn line, {set, state} ->
        cond do
          line == "paths:" ->
            {set, :paths}

          state == :paths and Regex.match?(~r/^[a-zA-Z]/, line) ->
            # We've left the `paths:` section.
            {set, :outside}

          state == :paths and Regex.match?(~r/^  \//, line) ->
            current_path =
              line
              |> String.trim()
              |> String.trim_trailing(":")

            {set, {:path, current_path}}

          state == :paths and line == "" ->
            {set, :paths}

          match?({:path, _}, state) and Regex.match?(~r/^    [a-z]+:/, line) ->
            {:path, current_path} = state
            method = line |> String.trim() |> String.trim_trailing(":") |> String.upcase()

            if method in ~w(GET POST PATCH DELETE PUT HEAD) do
              {MapSet.put(set, {method, current_path}), state}
            else
              {set, state}
            end

          match?({:path, _}, state) and Regex.match?(~r/^  \//, line) ->
            current_path =
              line
              |> String.trim()
              |> String.trim_trailing(":")

            {set, {:path, current_path}}

          match?({:path, _}, state) and Regex.match?(~r/^[a-zA-Z]/, line) ->
            {set, :outside}

          true ->
            {set, state}
        end
      end)

    paths
  end

  defp collect_router_paths do
    # `Plug.Router` builds a private list of routes via macros.
    # We can recover them from the module's compiled docs in a
    # robust way — by walking `__routes__/0` if it's exposed,
    # else by introspecting `__plugs__/0`-equivalent helpers.
    # ExDns.API.Router uses Plug.Router which generates a
    # `__match_pattern__/4` clause per route. We compute the
    # routes from the source file instead — simpler and avoids
    # depending on Plug internals.
    source =
      ExDns.API.Router.__info__(:compile)
      |> Keyword.get(:source)
      |> List.to_string()
      |> File.read!()

    source
    |> String.split("\n")
    |> Enum.flat_map(&match_route_line/1)
    |> MapSet.new()
  end

  defp match_route_line(line) do
    case Regex.run(~r/^\s*(get|post|patch|delete|put)\s+"([^"]+)"/, line) do
      [_, method, path] ->
        normalised = normalise_router_path(path)
        [{String.upcase(method), normalised}]

      _ ->
        []
    end
  end

  # Plug.Router uses ":apex"; OpenAPI uses "{apex}". Normalise
  # router-side to OpenAPI shape so comparison is meaningful.
  defp normalise_router_path(path) do
    Regex.replace(~r/:([a-zA-Z_][a-zA-Z_0-9]*)/, path, "{\\1}")
  end

  defp report(_label, set) do
    if MapSet.size(set) > 0 do
      Mix.shell().error("\n" <> _label_to_str(_label))

      Enum.each(Enum.sort(MapSet.to_list(set)), fn {method, path} ->
        Mix.shell().error("  #{method} #{path}")
      end)
    end

    :ok
  end

  defp _label_to_str(label), do: label
end
