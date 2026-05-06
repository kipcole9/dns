defmodule ExDns.PauseMode do
  @moduledoc """
  "Big red button" for operators: when paused, every plugin
  (BlackHole filtering, Anycast synthesis, mDNS routing) is
  bypassed and queries flow straight to the underlying
  resolver. The DNS service itself stays up — DNS keeps
  resolving — but anything an operator might have
  misconfigured is taken out of the path.

  ## Why this exists

  A pi-hole-class operator who breaks their config needs a
  one-click "make DNS work again" button. They can flip
  this on, fix the misconfiguration on the dashboard, then
  flip it back off.

  ## Mechanics

  Pause state lives in `:persistent_term`. The plugin
  pipeline (`ExDns.Resolver.Plugins`) checks `paused?/0` on
  every query before consulting the registry. When paused,
  it short-circuits to the underlying resolver.

  ## Auto-resume

  `pause/1` takes a duration (seconds) or `:until_unpaused`.
  Bounded pauses arrange a self-clearing timer so an
  operator who sets a 5-minute pause and forgets doesn't
  leave their server in pass-through forever.

  ## Configuration

  No knobs — pause is a runtime concern, not config-as-code.
  """

  @key {__MODULE__, :state}

  @doc """
  Pause the plugin pipeline.

  ### Arguments

  * `duration` — `:until_unpaused` for an indefinite pause,
    or a positive integer in seconds for a self-clearing one.

  ### Returns

  * `:ok`.
  """
  @spec pause(:until_unpaused | pos_integer()) :: :ok
  def pause(:until_unpaused), do: do_pause(nil)

  def pause(seconds) when is_integer(seconds) and seconds > 0 do
    expires_at = System.os_time(:second) + seconds
    do_pause(expires_at)
  end

  defp do_pause(expires_at) do
    :persistent_term.put(@key, %{paused: true, expires_at: expires_at})
    :ok
  end

  @doc "Resume the plugin pipeline. Idempotent."
  @spec unpause() :: :ok
  def unpause do
    :persistent_term.put(@key, %{paused: false, expires_at: nil})
    :ok
  end

  @doc """
  Whether the plugin pipeline is currently paused. The
  hot-path version — checked on every query — so it has to
  be fast.

  Auto-clears an expired bounded pause on read so the next
  query goes through the resolver without the operator
  having to flip the switch.
  """
  @spec paused?() :: boolean()
  def paused? do
    case :persistent_term.get(@key, default()) do
      %{paused: false} ->
        false

      %{paused: true, expires_at: nil} ->
        true

      %{paused: true, expires_at: exp} ->
        if System.os_time(:second) >= exp do
          unpause()
          false
        else
          true
        end
    end
  end

  @doc """
  Status snapshot for the UI / API.

  ### Returns

  * `%{paused: false}` when not paused.
  * `%{paused: true, expires_at: integer | nil, remaining_seconds: integer | nil}`
    when paused.
  """
  @spec status() :: map()
  def status do
    case :persistent_term.get(@key, default()) do
      %{paused: false} = s ->
        Map.take(s, [:paused])

      %{paused: true, expires_at: nil} ->
        %{paused: true, expires_at: nil, remaining_seconds: nil}

      %{paused: true, expires_at: exp} ->
        remaining = max(exp - System.os_time(:second), 0)

        if remaining == 0 do
          unpause()
          %{paused: false}
        else
          %{paused: true, expires_at: exp, remaining_seconds: remaining}
        end
    end
  end

  defp default, do: %{paused: false, expires_at: nil}
end
