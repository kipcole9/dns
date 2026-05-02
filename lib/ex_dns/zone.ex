defmodule ExDns.Zone do
  @moduledoc """
  An authoritative DNS zone in memory.

  A zone is the parsed, validated, in-memory representation of a zone
  file: a set of `$ORIGIN`/`$TTL`-style directives plus the list of
  resource record structs that belong to the zone.

  Loading a zone into the in-memory store happens through
  `load_file/1` or `load_string/2`, which parse the zone, validate
  records, and hand the records off to `ExDns.Storage.ETS.put_zone/2`.

  """

  alias ExDns.Resource
  alias ExDns.Storage
  alias ExDns.Zone.File, as: ZoneFile

  defstruct [:directives, :resources]

  @type t :: %__MODULE__{
          directives: keyword(),
          resources: [struct()]
        }

  @doc """
  Builds a `%Zone{}` from a keyword list of `:directives` and
  `:resources`. Used internally by the zone-file pipeline.
  """
  def new(args) do
    struct(__MODULE__, args)
  end

  @doc """
  Returns the zone's apex name (the `:name` of its SOA record).

  Raises if the zone has no SOA record.
  """
  def name(%__MODULE__{} = zone), do: soa(zone).name

  @doc """
  Returns the zone's SOA resource record struct.

  Raises if the zone has no SOA record.
  """
  def soa(%__MODULE__{resources: resources}) do
    Enum.find(resources, fn record ->
      record.__struct__ == Resource.SOA
    end) || raise "Zone has no SOA record"
  end

  @doc """
  Loads a zone file from disk and inserts its records into the
  in-memory store.

  ### Arguments

  * `path` is the absolute or relative path to a BIND-style zone file.

  ### Returns

  * `{:ok, %Zone{}}` on success — the zone is also registered in
    `ExDns.Storage.ETS` under its SOA's apex name.

  * `{:error, reason}` if the file cannot be read or the zone cannot be
    parsed.

  """
  @spec load_file(Path.t()) :: {:ok, t()} | {:error, term()}
  def load_file(path) do
    with {:ok, contents} <- File.read(path),
         {:ok, zone} <- load_string(contents) do
      {:ok, zone}
    end
  end

  @doc """
  Parses a zone-file string and inserts its records into the in-memory
  store.

  ### Arguments

  * `string` is the zone-file text.

  * `options` is a keyword list:

  ### Options

  * `:store?` — when `true` (the default) the parsed zone is also
    registered with `ExDns.Storage.ETS`. Pass `false` to parse without
    storing.

  ### Returns

  * `{:ok, %Zone{}}` on success.

  * `{:error, reason}` on parse failure.

  """
  @spec load_string(binary(), keyword()) :: {:ok, t()} | {:error, term()}
  def load_string(string, options \\ []) when is_binary(string) do
    store? = Keyword.get(options, :store?, true)

    case ZoneFile.process(string) do
      %__MODULE__{} = zone ->
        if store?, do: store!(zone)
        {:ok, zone}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Inserts (or replaces) the zone in `ExDns.Storage.ETS` under the SOA
  apex.
  """
  @spec store!(t()) :: :ok
  def store!(%__MODULE__{} = zone) do
    apex = name(zone)
    Storage.put_zone(apex, zone.resources)
  end
end
