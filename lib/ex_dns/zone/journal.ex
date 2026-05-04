defmodule ExDns.Zone.Journal do
  @moduledoc """
  Per-zone change journal supporting RFC 1995 IXFR.

  Each entry records the delta between two consecutive serials of a
  single zone:

      %Entry{
        apex:         "example.test",
        from_serial:  41,
        to_serial:    42,
        removed:      [%A{...}, ...],   # records present at 41 but not 42
        added:        [%A{...}, ...]    # records present at 42 but not 41
      }

  Entries are append-only and ordered by `to_serial`. An IXFR
  responder calls `since/2` to retrieve every delta a secondary needs
  to catch up from the serial it last saw to the current one.

  ## Storage

  Entries live in a single ETS table (`@table`). Production
  deployments that need durability across restarts should swap the
  backend for a disk-backed implementation (DETS, RocksDB, etc.); the
  public API here is the seam for that swap.

  ## Wiring

  `ExDns.Storage.put_zone/2` records a journal entry automatically
  when an existing zone is being replaced and the new SOA serial is
  greater than the old one. Callers don't need to invoke `record/3`
  directly.
  """

  alias ExDns.Resource.SOA

  @table :ex_dns_zone_journal

  defmodule Entry do
    @moduledoc """
    A single journal entry: one delta between two consecutive
    serials of a zone.
    """
    defstruct [:apex, :from_serial, :to_serial, :removed, :added]

    @type t :: %__MODULE__{
            apex: binary(),
            from_serial: non_neg_integer(),
            to_serial: non_neg_integer(),
            removed: [struct()],
            added: [struct()]
          }
  end

  @doc """
  Initialise the journal table. Idempotent.

  ### Returns

  * The atom name of the journal ETS table.

  ### Examples

      iex> ExDns.Zone.Journal.init()
      :ex_dns_zone_journal

  """
  @spec init() :: atom()
  def init do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [
          :ordered_set,
          :named_table,
          :public,
          read_concurrency: true,
          write_concurrency: true
        ])

      _ ->
        @table
    end

    @table
  end

  @doc """
  Drop every journal entry. Used by tests.

  ### Returns

  * `:ok`.

  ### Examples

      iex> ExDns.Zone.Journal.clear()
      :ok

  """
  @spec clear() :: :ok
  def clear do
    init()
    :ets.delete_all_objects(@table)
    :ok
  end

  @doc """
  Compute and record the journal entry between `old_records` and
  `new_records`.

  The function picks the SOA out of each record list to determine
  the from/to serials and computes the symmetric difference of the
  two record sets.

  ### Arguments

  * `apex` is the zone apex (binary).
  * `old_records` is the previously stored record list.
  * `new_records` is the replacement record list.

  ### Returns

  * `{:ok, entry}` — the journal entry that was recorded.
  * `:no_change` — the new SOA is identical to the old one (or the
    zone is being created from scratch).
  * `{:error, :no_soa}` — neither side has a usable SOA.
  * `{:error, :serial_did_not_advance}` — the new serial is not
    greater than the old serial. RFC 1982 wraparound is honoured.

  ### Examples

      iex> alias ExDns.Resource.{SOA, A}
      iex> ExDns.Zone.Journal.clear()
      iex> old_records = [
      ...>   %SOA{name: "example.test", ttl: 60, class: :in, mname: "ns", email: "h", serial: 1, refresh: 1, retry: 1, expire: 1, minimum: 1},
      ...>   %A{name: "host.example.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 1}}
      ...> ]
      iex> new_records = [
      ...>   %SOA{name: "example.test", ttl: 60, class: :in, mname: "ns", email: "h", serial: 2, refresh: 1, retry: 1, expire: 1, minimum: 1},
      ...>   %A{name: "host.example.test", ttl: 60, class: :in, ipv4: {1, 1, 1, 2}}
      ...> ]
      iex> {:ok, entry} = ExDns.Zone.Journal.record("example.test", old_records, new_records)
      iex> entry.from_serial
      1

  """
  @spec record(binary(), [struct()], [struct()]) ::
          {:ok, Entry.t()} | :no_change | {:error, :no_soa | :serial_did_not_advance}
  def record(apex, old_records, new_records)
      when is_binary(apex) and is_list(old_records) and is_list(new_records) do
    init()

    with {:ok, old_serial} <- find_serial(old_records),
         {:ok, new_serial} <- find_serial(new_records),
         :ok <- check_advanced(old_serial, new_serial) do
      added = new_records -- old_records
      removed = old_records -- new_records

      entry = %Entry{
        apex: normalize(apex),
        from_serial: old_serial,
        to_serial: new_serial,
        removed: removed,
        added: added
      }

      :ets.insert(@table, {{normalize(apex), new_serial}, entry})
      {:ok, entry}
    else
      {:error, :no_soa} -> {:error, :no_soa}
      {:error, :no_change} -> :no_change
      {:error, :serial_did_not_advance} -> {:error, :serial_did_not_advance}
    end
  end

  @doc """
  Returns every journal entry for `apex` whose `from_serial` is at
  or after `from`, ordered by `to_serial` ascending.

  An IXFR responder uses this to walk the chain from the serial the
  client knows up to the current one.

  ### Arguments

  * `apex` is the zone apex (binary).
  * `from_serial` is the serial the client currently holds.

  ### Returns

  * A list of `Entry` structs. Empty list means either the apex is
    unknown or the client is already up-to-date.

  ### Examples

      iex> ExDns.Zone.Journal.clear()
      iex> ExDns.Zone.Journal.since("example.test", 0)
      []

  """
  @spec since(binary(), non_neg_integer()) :: [Entry.t()]
  def since(apex, from_serial)
      when is_binary(apex) and is_integer(from_serial) and from_serial >= 0 do
    init()
    apex = normalize(apex)

    @table
    |> :ets.match_object({{apex, :"$1"}, :"$2"})
    |> Enum.map(fn {{_, _serial}, entry} -> entry end)
    |> Enum.filter(fn %Entry{from_serial: from} -> from >= from_serial end)
    |> Enum.sort_by(& &1.to_serial)
  end

  @doc """
  Returns the highest `to_serial` recorded for `apex`, or `nil` if
  the zone has no journal entries yet.

  ### Arguments

  * `apex` is the zone apex.

  ### Returns

  * The serial as an integer, or `nil`.

  ### Examples

      iex> ExDns.Zone.Journal.clear()
      iex> ExDns.Zone.Journal.latest_serial("nonexistent")
      nil

  """
  @spec latest_serial(binary()) :: non_neg_integer() | nil
  def latest_serial(apex) when is_binary(apex) do
    init()
    apex = normalize(apex)

    @table
    |> :ets.match_object({{apex, :"$1"}, :"$2"})
    |> Enum.map(fn {{_, serial}, _} -> serial end)
    |> case do
      [] -> nil
      serials -> Enum.max(serials)
    end
  end

  # ---- helpers ----

  defp find_serial(records) do
    case Enum.find(records, &match?(%SOA{}, &1)) do
      %SOA{serial: serial} when is_integer(serial) -> {:ok, serial}
      _ -> {:error, :no_soa}
    end
  end

  defp check_advanced(old, new) when new == old, do: {:error, :no_change}

  defp check_advanced(old, new) when is_integer(old) and is_integer(new) do
    # RFC 1982 serial-number arithmetic: new is "later" than old if
    # `0 < (new - old) mod 2^32 < 2^31`.
    diff = rem(new - old + 0x100000000, 0x100000000)

    if diff > 0 and diff < 0x80000000 do
      :ok
    else
      {:error, :serial_did_not_advance}
    end
  end

  defp normalize(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end
end
