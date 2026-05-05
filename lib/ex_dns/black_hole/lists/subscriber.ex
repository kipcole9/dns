defmodule ExDns.BlackHole.Lists.Subscriber do
  @moduledoc """
  GenServer that periodically fetches one blocklist URL and,
  on success, asks the plugin to recompile its match set.

  ## Behaviour

  * Init: schedule the first fetch immediately (subject to
    a small jitter so a fleet of subscribers doesn't all fire
    at once on boot).
  * Tick: call `Fetcher.fetch/2` with stored validators
    (etag + last-modified) so 304s are cheap.
  * On 200: parse via `Parser.parse/1`, write the parsed
    domains into the storage row's `domains` slot, and signal
    the plugin to recompile.
  * On 304: bump `last_refresh` only.
  * On error: log + count, leave compiled set alone.

  Failures never crash the subscriber — operators see them
  via the `last_status` field on the blocklist row.

  ## Telemetry

  * `[:ex_dns, :black_hole, :list, :refreshed]` — `%{list_id,
    status, entries}` on every cycle.
  """

  use GenServer

  alias ExDns.BlackHole.Lists.{Fetcher, Parser}
  alias ExDns.BlackHole.Storage

  require Logger

  @default_interval_ms 86_400_000

  # ----- public --------------------------------------------------

  @doc """
  Start a subscriber for one blocklist row.

  ### Required keys

  * `:id` — blocklist id (binary).
  * `:url` — adlist URL (binary).
  * `:on_refresh` — 1-arity function called with the parsed
    domain list after a successful fetch. The plugin uses
    this hook to trigger a recompile + install of the
    match set.

  ### Optional keys

  * `:interval_ms` — refresh interval (default 24h).
  * `:initial_delay_ms` — wait this long before the first
    tick (default `:rand.uniform(30_000)`).
  * `:req_options` — passed straight through to `Req`
    (used by tests with the `:plug` adapter).
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options) do
    id = Keyword.fetch!(options, :id)
    GenServer.start_link(__MODULE__, options, name: server_name(id))
  end

  @doc "Trigger an immediate fetch on the named subscriber."
  @spec refresh_now(binary()) :: :ok | {:error, :not_running}
  def refresh_now(id) when is_binary(id) do
    case GenServer.whereis(server_name(id)) do
      nil -> {:error, :not_running}
      pid -> GenServer.cast(pid, :refresh_now)
    end
  end

  @doc "Inspect a subscriber's current state. Test helper."
  @spec snapshot(binary()) :: map() | nil
  def snapshot(id) when is_binary(id) do
    case GenServer.whereis(server_name(id)) do
      nil -> nil
      pid -> GenServer.call(pid, :snapshot)
    end
  end

  defp server_name(id), do: {:global, {__MODULE__, id}}

  # ----- callbacks ----------------------------------------------

  @impl true
  def init(options) do
    state = %{
      id: Keyword.fetch!(options, :id),
      url: Keyword.fetch!(options, :url),
      on_refresh: Keyword.fetch!(options, :on_refresh),
      interval_ms: Keyword.get(options, :interval_ms, @default_interval_ms),
      req_options: Keyword.get(options, :req_options, []),
      etag: nil,
      last_modified: nil,
      last_status: nil,
      last_refresh_unix: nil,
      entries: 0
    }

    delay = Keyword.get(options, :initial_delay_ms, :rand.uniform(30_000))
    Process.send_after(self(), :tick, delay)
    {:ok, state}
  end

  @impl true
  def handle_info(:tick, state), do: do_fetch(state)

  @impl true
  def handle_cast(:refresh_now, state), do: do_fetch(state)

  @impl true
  def handle_call(:snapshot, _from, state), do: {:reply, snapshot_data(state), state}

  defp snapshot_data(state) do
    %{
      id: state.id,
      url: state.url,
      etag: state.etag,
      last_modified: state.last_modified,
      last_status: state.last_status,
      last_refresh_unix: state.last_refresh_unix,
      entries: state.entries
    }
  end

  defp do_fetch(state) do
    fetched_at = System.os_time(:second)

    options = [
      etag: state.etag,
      last_modified: state.last_modified,
      req_options: state.req_options
    ]

    new_state =
      case Fetcher.fetch(state.url, options) do
        {:ok, %{body: body, etag: etag, last_modified: lm}} ->
          domains = Parser.parse(body)
          state.on_refresh.({state.id, domains})
          persist_validators(state.id, etag, lm, fetched_at, "200", length(domains))
          emit(state.id, "200", length(domains))

          %{
            state
            | etag: etag,
              last_modified: lm,
              last_status: "200",
              last_refresh_unix: fetched_at,
              entries: length(domains)
          }

        {:not_modified, %{etag: etag, last_modified: lm}} ->
          persist_validators(state.id, etag, lm, fetched_at, "304", state.entries)
          emit(state.id, "304", state.entries)

          %{
            state
            | etag: etag || state.etag,
              last_modified: lm || state.last_modified,
              last_status: "304",
              last_refresh_unix: fetched_at
          }

        {:error, reason} ->
          status = "error: #{inspect(reason)}"
          Logger.warning("BlackHole subscriber #{state.id} fetch failed: #{status}")
          persist_validators(state.id, state.etag, state.last_modified, fetched_at, status, state.entries)
          emit(state.id, status, 0)

          %{state | last_status: status, last_refresh_unix: fetched_at}
      end

    Process.send_after(self(), :tick, state.interval_ms)
    {:noreply, new_state}
  end

  defp persist_validators(id, etag, lm, ts, status, entries) do
    # Best-effort: if the storage backend isn't initialised in
    # tests we silently skip.
    try do
      [row] =
        Storage.list_blocklists()
        |> Enum.filter(fn r -> r["id"] == id end)
        |> case do
          [] -> [%{"id" => id, "url" => "", "name" => nil, "enabled" => true}]
          rs -> rs
        end

      updated =
        row
        |> Map.put("last_refresh_unix", ts)
        |> Map.put("last_status", status)
        |> Map.put("hash", encode_validators(etag, lm))
        |> Map.put("entries", entries)

      Storage.put_blocklist(updated)
    rescue
      _ -> :ok
    catch
      _, _ -> :ok
    end
  end

  defp encode_validators(nil, nil), do: nil
  defp encode_validators(etag, lm), do: "etag=#{etag || ""};lm=#{lm || ""}"

  defp emit(id, status, entries) do
    :telemetry.execute(
      [:ex_dns, :black_hole, :list, :refreshed],
      %{count: 1, entries: entries},
      %{list_id: id, status: status}
    )
  end
end
