defmodule ExDns.API.Auth.Throttle do
  @moduledoc """
  Per-source-IP throttle for `/api/v1` authentication failures.

  Online password / token brute-forcing is the standard way an
  attacker turns a leaked credential reference into a working
  one. Constant-time secret comparison defeats *timing* leaks
  but does nothing to slow the attempt rate. This module adds
  a small in-memory token bucket per remote IP that keys on
  authentication outcome:

  * **Successful** auth refills the bucket (good actors are
    not throttled).
  * **Failed** auth (no token / wrong token / expired token)
    decrements the bucket. When the bucket runs dry the IP
    is rejected with `429 Too Many Requests` for the cooldown
    window.

  The bucket lives in an ETS table created on demand. Wiped
  on application restart — restoring brute-force budget to
  attackers across a restart isn't worth the persistence cost
  for what is, by design, an emergency brake.

  ## Configuration

      config :ex_dns, :api_auth_throttle,
        enabled: true,                   # default
        burst: 10,                       # failures permitted in burst
        refill_seconds: 60,              # +1 token every N seconds
        cooldown_seconds: 300            # how long an empty bucket stays empty

  Set `enabled: false` to bypass entirely (not recommended in
  production; useful for tests that hammer the API).
  """

  @table :ex_dns_api_auth_throttle

  @default_burst 10
  @default_refill_seconds 60
  @default_cooldown_seconds 300

  @doc "Initialise the throttle table. Idempotent. Safe to call from boot."
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
  Check whether `ip` may attempt authentication right now.

  ### Returns

  * `:ok` — proceed with the auth attempt.

  * `{:error, :throttled, retry_after_seconds}` — bucket is
    empty; the plug returns `429 Too Many Requests` with
    `Retry-After: retry_after_seconds`.

  ### Examples

      iex> ExDns.API.Auth.Throttle.check({127, 0, 0, 1})
      :ok

  """
  @spec check(:inet.ip_address() | nil) :: :ok | {:error, :throttled, non_neg_integer()}
  def check(nil), do: :ok

  def check(ip) do
    if enabled?() do
      do_check(ip, System.os_time(:second))
    else
      :ok
    end
  end

  defp do_check(ip, now) do
    init()
    config = config()

    case :ets.lookup(@table, ip) do
      [] ->
        :ok

      [{^ip, tokens, last_refill}] ->
        refilled = refill(tokens, last_refill, now, config)

        if refilled > 0 do
          :ok
        else
          retry_after = max(config.cooldown_seconds - (now - last_refill), 1)
          {:error, :throttled, retry_after}
        end
    end
  end

  @doc """
  Record an authentication failure from `ip`. Decrements the
  bucket; the next `check/1` may return `{:error, :throttled, …}`.
  """
  @spec record_failure(:inet.ip_address() | nil) :: :ok
  def record_failure(nil), do: :ok

  def record_failure(ip) do
    if enabled?() do
      init()
      config = config()
      now = System.os_time(:second)

      case :ets.lookup(@table, ip) do
        [] ->
          # First failure — start the bucket at burst-1.
          :ets.insert(@table, {ip, config.burst - 1, now})

        [{^ip, tokens, last_refill}] ->
          refilled = refill(tokens, last_refill, now, config)
          new_tokens = max(refilled - 1, 0)
          :ets.insert(@table, {ip, new_tokens, now})
      end

      :ok
    else
      :ok
    end
  end

  @doc """
  Record a successful authentication from `ip`. Drops the IP
  from the throttle table — good actors aren't slowed down.
  """
  @spec record_success(:inet.ip_address() | nil) :: :ok
  def record_success(nil), do: :ok

  def record_success(ip) do
    init()
    :ets.delete(@table, ip)
    :ok
  end

  @doc false
  def reset do
    init()
    :ets.delete_all_objects(@table)
    :ok
  end

  defp refill(tokens, last_refill, now, %{refill_seconds: refill_seconds, burst: burst}) do
    elapsed = max(now - last_refill, 0)
    added = div(elapsed, refill_seconds)
    min(tokens + added, burst)
  end

  defp enabled? do
    Application.get_env(:ex_dns, :api_auth_throttle, [])
    |> Keyword.get(:enabled, true)
  end

  defp config do
    options = Application.get_env(:ex_dns, :api_auth_throttle, [])

    %{
      burst: Keyword.get(options, :burst, @default_burst),
      refill_seconds: Keyword.get(options, :refill_seconds, @default_refill_seconds),
      cooldown_seconds: Keyword.get(options, :cooldown_seconds, @default_cooldown_seconds)
    }
  end
end
