defmodule ExDns.Update.TSIG.Replay do
  @moduledoc """
  Per-key MAC replay cache for inbound RFC 2136 UPDATEs.

  TSIG (RFC 8945) authenticates a message but, on its own,
  does not protect against replay: an attacker who captures a
  signed UPDATE has the full TSIG fudge window (default 300s)
  to resend it. For zone transfers that's mostly cosmetic
  (the same diff lands twice). For UPDATEs it's a real risk:
  a replayed `delete + add` reverts a record after the
  operator just changed it.

  This module records every accepted UPDATE TSIG MAC for the
  duration of the fudge window and refuses any second
  attempt with the same MAC.

  ## Storage

  ETS, in-process, wiped on application restart. The window
  is short and the surface area small; persistence would be
  more complexity than it's worth for the protection
  provided.

  ## Configuration

      config :ex_dns, :tsig_replay,
        enabled: true,                # default
        window_seconds: 300,          # match TSIG fudge default
        max_entries: 10_000           # safety cap
  """

  @table :ex_dns_tsig_replay
  @default_window_seconds 300
  @default_max_entries 10_000

  @doc "Initialise the replay table. Idempotent."
  @spec init() :: :ok
  def init do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [
          :set,
          :public,
          :named_table,
          read_concurrency: true,
          write_concurrency: true
        ])

        :ok

      _ ->
        :ok
    end
  end

  @doc """
  Record an accepted (key_name, mac) pair. Returns

  * `:ok` — the MAC was not previously seen and is now
    remembered for the configured window.

  * `{:error, :replay}` — this exact MAC has been accepted
    inside the window. The caller MUST refuse the request.

  When the feature is disabled (`enabled: false`) every call
  returns `:ok`.
  """
  @spec record(binary(), binary()) :: :ok | {:error, :replay}
  def record(key_name, mac) when is_binary(key_name) and is_binary(mac) do
    if enabled?() do
      do_record(key_name, mac, System.os_time(:second))
    else
      :ok
    end
  end

  defp do_record(key_name, mac, now) do
    init()
    config = config()
    key = {key_name, mac}

    case :ets.lookup(@table, key) do
      [{^key, expires_at}] when expires_at > now ->
        {:error, :replay}

      _ ->
        if :ets.info(@table, :size) >= config.max_entries do
          reap_expired(now)
        end

        :ets.insert(@table, {key, now + config.window_seconds})
        :ok
    end
  end

  defp reap_expired(now) do
    :ets.select_delete(@table, [
      {{:_, :"$1"}, [{:"=<", :"$1", now}], [true]}
    ])
  end

  @doc false
  def reset do
    init()
    :ets.delete_all_objects(@table)
    :ok
  end

  defp enabled? do
    Application.get_env(:ex_dns, :tsig_replay, [])
    |> Keyword.get(:enabled, true)
  end

  defp config do
    options = Application.get_env(:ex_dns, :tsig_replay, [])

    %{
      window_seconds: Keyword.get(options, :window_seconds, @default_window_seconds),
      max_entries: Keyword.get(options, :max_entries, @default_max_entries)
    }
  end
end
