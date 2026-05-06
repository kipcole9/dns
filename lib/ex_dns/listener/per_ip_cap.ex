defmodule ExDns.Listener.PerIPCap do
  @moduledoc """
  Per-source-IP concurrent-connection cap for stream-style
  listeners (TCP, DoT, DoH).

  ThousandIsland and Bandit have a global `num_connections`
  knob (default 16384) but no per-IP cap. A single misbehaving
  client — slow-loris, leaked-keepalive, deliberate exhaustion
  — can therefore consume an outsized share of the listener's
  budget. This module adds a small ETS counter per source IP
  and refuses new connections from any IP that's already at
  its individual limit.

  ## Public API

  * `acquire/1` — call from the listener's `handle_connection/2`
    callback before doing any work. Returns `:ok` to proceed
    or `{:error, :over_cap}` to refuse + close.

  * `release/1` — call from the close path (matching every
    successful `acquire/1`) to decrement the counter.

  Both are O(1) ETS operations.

  ## Configuration

      config :ex_dns, :per_ip_cap,
        enabled: true,                # default
        max_per_ip: 64                # default

  Set `enabled: false` to short-circuit (returns `:ok` always).
  Set `max_per_ip: 0` to refuse every new connection (useful
  in tests).
  """

  @table :ex_dns_per_ip_cap

  @default_max_per_ip 64

  @doc "Initialise the counter table. Idempotent."
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
  Reserve one connection slot for `ip`. Atomically increments
  the per-IP counter and refuses if the post-increment value
  exceeds the configured cap.

  ### Returns

  * `:ok` — slot acquired; caller MUST eventually call
    `release/1` with the same IP.

  * `{:error, :over_cap}` — too many concurrent connections
    from this IP; the caller should close immediately.

  ### Examples

      iex> ExDns.Listener.PerIPCap.acquire({127, 0, 0, 1})
      :ok

  """
  @spec acquire(:inet.ip_address() | nil) :: :ok | {:error, :over_cap}
  def acquire(nil), do: :ok

  def acquire(ip) do
    if enabled?() do
      do_acquire(ip, max_per_ip())
    else
      :ok
    end
  end

  defp do_acquire(_ip, max) when max <= 0, do: {:error, :over_cap}

  defp do_acquire(ip, max) do
    init()
    new_count = :ets.update_counter(@table, ip, {2, 1}, {ip, 0})

    if new_count > max do
      # Roll back our own increment — we are not consuming
      # the slot — so subsequent legitimate connections
      # from this IP can still be admitted as the counter
      # decays.
      :ets.update_counter(@table, ip, {2, -1, 0, 0})
      {:error, :over_cap}
    else
      :ok
    end
  end

  @doc """
  Release one connection slot for `ip`. Idempotent at the
  zero floor — over-release does not create a negative
  counter.
  """
  @spec release(:inet.ip_address() | nil) :: :ok
  def release(nil), do: :ok

  def release(ip) do
    if enabled?() do
      init()
      :ets.update_counter(@table, ip, {2, -1, 0, 0}, {ip, 0})
      :ok
    else
      :ok
    end
  end

  @doc false
  def reset do
    init()
    :ets.delete_all_objects(@table)
    :ok
  end

  @doc false
  def count(ip) do
    init()

    case :ets.lookup(@table, ip) do
      [{^ip, n}] -> n
      [] -> 0
    end
  end

  defp enabled? do
    Application.get_env(:ex_dns, :per_ip_cap, [])
    |> Keyword.get(:enabled, true)
  end

  defp max_per_ip do
    Application.get_env(:ex_dns, :per_ip_cap, [])
    |> Keyword.get(:max_per_ip, @default_max_per_ip)
  end
end
