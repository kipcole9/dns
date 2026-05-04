defmodule ExDns.Zone.Journal.Storage.DETS do
  @moduledoc """
  Disk-backed DETS storage for the IXFR journal.

  Survives application restarts so secondaries can resume IXFR
  from the serial they last saw rather than full-AXFRing on every
  bounce of the primary.

  ## Configuration

      config :ex_dns, :journal,
        backend: ExDns.Zone.Journal.Storage.DETS,
        path: "/var/lib/exdns/journal.dets"

  The DETS file is opened lazily on first use. `auto_save` is set
  to `1000ms` so a crash loses at most one second of journal
  entries.

  ## Limitations

  DETS is single-writer with a 2GB file-size cap. For larger or
  multi-node deployments, swap in a custom backend conforming to
  `ExDns.Zone.Journal.Storage`.
  """

  @behaviour ExDns.Zone.Journal.Storage

  @table :ex_dns_zone_journal_dets

  @impl true
  def init(options) do
    case :dets.info(@table) do
      :undefined ->
        path =
          options
          |> Keyword.get(:path)
          |> case do
            nil -> raise ":ex_dns, :journal requires :path when using the DETS backend"
            p -> p
          end

        File.mkdir_p!(Path.dirname(path))

        {:ok, @table} =
          :dets.open_file(@table,
            file: String.to_charlist(path),
            type: :set,
            auto_save: 1_000
          )

      _ ->
        :ok
    end

    @table
  end

  @impl true
  def clear do
    init(ExDns.Zone.Journal.Storage.backend_options())
    :dets.delete_all_objects(@table)
    :ok
  end

  @impl true
  def insert(apex, serial, entry) do
    init(ExDns.Zone.Journal.Storage.backend_options())
    :dets.insert(@table, {{apex, serial}, entry})
    # Force the change to disk on every write — secondaries depend
    # on the journal being durable across crashes.
    :ok = :dets.sync(@table)
    :ok
  end

  @impl true
  def entries(apex) do
    init(ExDns.Zone.Journal.Storage.backend_options())

    @table
    |> :dets.match_object({{apex, :"$1"}, :"$2"})
    |> Enum.map(fn {{_, _serial}, entry} -> entry end)
  end

  @doc """
  Close the DETS file. Called from drain on graceful shutdown so
  pending writes make it to disk.

  ### Returns

  * `:ok`.
  """
  @spec close() :: :ok
  def close do
    case :dets.info(@table) do
      :undefined -> :ok
      _ -> :dets.close(@table)
    end

    :ok
  end
end
