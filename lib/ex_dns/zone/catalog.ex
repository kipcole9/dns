defmodule ExDns.Zone.Catalog do
  @moduledoc """
  Catalog zones (RFC 9432) — a single zone whose contents
  enumerate the *member* zones a secondary should be serving.

  Without catalogs, every secondary needs its zone list shipped
  out-of-band (config files, CMDB, etc.) and kept in sync with
  the primary's. With catalogs, the secondary subscribes to one
  control zone and discovers/un-discovers members automatically
  as the primary edits the catalog and bumps its serial.

  ## Wire layout

      catalog.example.            SOA ...
      catalog.example.            NS  ns.example.
      version.catalog.example.    TXT "2"

      <opaque>.zones.catalog.example.       PTR member-zone.test.
      coo.<opaque>.zones.catalog.example.   PTR primary.example.   (optional)
      group.<opaque>.zones.catalog.example. TXT "production"        (optional)

  The leading label of each member entry is opaque — RFC 9432
  §4.2 explicitly allows any unique label, so producers commonly
  use a hash. ExDns treats the label as a stable id without
  interpreting it.

  ## What this module is

  A pure parser. Given the records that make up a catalog zone
  (e.g. the result of an AXFR), it returns the catalog version
  and the list of members with their associated properties:

      iex> records = [
      ...>   %ExDns.Resource.SOA{name: "catalog.example", ttl: 3600, class: :in,
      ...>                       mname: "ns", email: "h", serial: 1,
      ...>                       refresh: 1, retry: 1, expire: 1, minimum: 1},
      ...>   %ExDns.Resource.TXT{name: "version.catalog.example", ttl: 3600,
      ...>                       class: :in, strings: ["2"]},
      ...>   %ExDns.Resource.PTR{name: "abc.zones.catalog.example", ttl: 3600,
      ...>                       class: :in, pointer: "first.test"},
      ...>   %ExDns.Resource.PTR{name: "xyz.zones.catalog.example", ttl: 3600,
      ...>                       class: :in, pointer: "second.test"}
      ...> ]
      iex> %{version: version, members: members} =
      ...>   ExDns.Zone.Catalog.parse("catalog.example", records)
      iex> {version, length(members)}
      {2, 2}

  ## What this module is NOT

  The dynamic state machine that subscribes to a catalog, polls
  the primary on the catalog's SOA refresh interval, diffs the
  member set, and starts/stops `ExDns.Zone.Secondary` instances
  is a follow-up that builds on this parser. For now,
  `apply_catalog/2` returns the diff so an operator can wire the
  reconciliation themselves or call it after a manual reload.
  """

  alias ExDns.Resource.{PTR, SOA, TXT}

  defmodule Member do
    @moduledoc """
    A single member zone of a catalog: the zone name plus any
    metadata properties the catalog attached to it.
    """
    defstruct [:id, :name, :coo, :group]

    @type t :: %__MODULE__{
            id: binary(),
            name: binary(),
            coo: binary() | nil,
            group: binary() | nil
          }
  end

  @doc """
  Parse a catalog zone's records into the catalog metadata + the
  member list.

  ### Arguments

  * `apex` — the catalog zone's apex (binary).
  * `records` — every record in the catalog zone (typically the
    result of an AXFR).

  ### Returns

  * `%{version: integer | nil, members: [Member.t()]}`. Members
    are returned in the order they appear in `records`.

  ### Examples

      iex> ExDns.Zone.Catalog.parse("catalog.example", []) |> Map.fetch!(:members)
      []

  """
  @spec parse(binary(), [struct()]) :: %{version: integer() | nil, members: [Member.t()]}
  def parse(apex, records) when is_binary(apex) and is_list(records) do
    apex_norm = canonical(apex)
    zones_suffix = "zones." <> apex_norm
    version_name = "version." <> apex_norm

    version =
      Enum.find_value(records, fn
        %TXT{name: name, strings: [v | _]} ->
          if canonical(name) == version_name do
            case Integer.parse(v) do
              {n, _} -> n
              :error -> nil
            end
          end

        _ ->
          nil
      end)

    # Group records under each `<opaque>.zones.<apex>` id, then
    # turn each group into a Member struct.
    by_id =
      records
      |> Enum.flat_map(fn record ->
        case classify(record, zones_suffix) do
          nil -> []
          {id, kind, value} -> [{id, kind, value}]
        end
      end)
      |> Enum.group_by(fn {id, _, _} -> id end)

    members =
      by_id
      |> Enum.flat_map(fn {id, entries} -> build_member(id, entries) end)

    %{version: version, members: members}
  end

  @doc """
  Diff a previous member set against a new one.

  ### Arguments

  * `previous` — the member list from the prior parse.
  * `current` — the member list from the most recent parse.

  ### Returns

  * `%{added: [Member.t()], removed: [Member.t()], changed: [Member.t()]}`.

  Members are matched by `:name`. A member that appears with the
  same name but different `:coo` or `:group` is treated as
  `:changed` (so the consumer can re-read those properties).

  ### Examples

      iex> ExDns.Zone.Catalog.diff([], []) |> Map.values() |> Enum.map(&length/1)
      [0, 0, 0]

  """
  @spec diff([Member.t()], [Member.t()]) ::
          %{added: [Member.t()], removed: [Member.t()], changed: [Member.t()]}
  def diff(previous, current) when is_list(previous) and is_list(current) do
    previous_by_name = Map.new(previous, fn m -> {m.name, m} end)
    current_by_name = Map.new(current, fn m -> {m.name, m} end)

    added =
      for m <- current, not Map.has_key?(previous_by_name, m.name), do: m

    removed =
      for m <- previous, not Map.has_key?(current_by_name, m.name), do: m

    changed =
      for m <- current,
          old = Map.get(previous_by_name, m.name),
          old != nil and (old.coo != m.coo or old.group != m.group),
          do: m

    %{added: added, removed: removed, changed: changed}
  end

  # ----- internals --------------------------------------------------

  # `name` looks like one of:
  #   <id>.zones.<apex>                 → {id, :name, <PTR target>}
  #   coo.<id>.zones.<apex>             → {id, :coo, <PTR target>}
  #   group.<id>.zones.<apex>           → {id, :group, <TXT first string>}
  # Anything else is :ignore.
  defp classify(%PTR{name: name, pointer: target}, suffix) do
    case strip_suffix(canonical(name), suffix) do
      nil ->
        nil

      stem ->
        case String.split(stem, ".", parts: 2) do
          [id] ->
            {id, :name, canonical(target)}

          ["coo", id] ->
            {id, :coo, canonical(target)}

          _ ->
            nil
        end
    end
  end

  defp classify(%TXT{name: name, strings: strings}, suffix) do
    case strip_suffix(canonical(name), suffix) do
      nil ->
        nil

      stem ->
        case String.split(stem, ".", parts: 2) do
          ["group", id] ->
            value = strings |> List.first() |> to_string()
            {id, :group, value}

          _ ->
            nil
        end
    end
  end

  defp classify(%SOA{}, _suffix), do: nil
  defp classify(_, _), do: nil

  defp build_member(id, entries) do
    case Enum.find_value(entries, fn
           {^id, :name, name} -> name
           _ -> nil
         end) do
      nil ->
        []

      name ->
        coo = Enum.find_value(entries, fn {^id, :coo, v} -> v; _ -> nil end)
        group = Enum.find_value(entries, fn {^id, :group, v} -> v; _ -> nil end)

        [%Member{id: id, name: name, coo: coo, group: group}]
    end
  end

  defp strip_suffix(name, suffix) when is_binary(name) and is_binary(suffix) do
    target = "." <> suffix

    if String.ends_with?(name, target) do
      stem_len = byte_size(name) - byte_size(target)
      binary_part(name, 0, stem_len)
    end
  end

  defp canonical(name) when is_binary(name) do
    name |> String.downcase(:ascii) |> String.trim_trailing(".")
  end
end
