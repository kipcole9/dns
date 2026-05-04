defmodule ExDns.Health do
  @moduledoc """
  Liveness and readiness probes for ExDns, exposed over HTTP for use
  by orchestrators (Kubernetes, systemd, load balancers).

  ## Routes

  * `GET /healthz` — liveness. Returns `200 ok` if the BEAM is up
    and responsive. Used by orchestrators to decide whether to
    restart the container/process.

  * `GET /readyz` — readiness. Returns `200 ready` only when every
    critical subsystem is up: storage initialised, recursor cache
    initialised, the DNS listeners bound. Returns `503` with a
    short body explaining which check failed otherwise. Used by
    load balancers to decide whether to route traffic here.

  ## Wiring

  When `:ex_dns, :health, [enabled: true, port: 9569]` is set the
  application supervisor starts a Bandit listener bound to the
  configured port. Off by default to keep the production footprint
  at zero until an operator opts in.

  Liveness is intentionally cheap: returning 200 unconditionally
  implies "the process is alive enough to handle this request".
  Readiness is the policy probe — fail it during startup or
  graceful shutdown to remove this node from the pool without
  restarting it.
  """

  use Plug.Router

  plug(:match)
  plug(:dispatch)

  get "/healthz" do
    send_resp(conn, 200, "ok\n")
  end

  get "/readyz" do
    case readiness_checks() do
      :ok ->
        send_resp(conn, 200, "ready\n")

      {:error, failures} ->
        body =
          ["not ready" | Enum.map(failures, fn {name, reason} -> "#{name}: #{inspect(reason)}" end)]
          |> Enum.join("\n")

        send_resp(conn, 503, body <> "\n")
    end
  end

  match _ do
    send_resp(conn, 404, "not found\n")
  end

  @doc """
  Run every readiness check and return either `:ok` or
  `{:error, [{check_name, reason}, …]}`.

  ### Returns

  * `:ok` when every check passed.

  * `{:error, failures}` when one or more checks failed; each
    failure is a `{atom, term}` pair giving the check name and the
    reason it failed.

  ### Examples

      iex> match?(:ok, ExDns.Health.readiness_checks()) or
      ...>   match?({:error, _}, ExDns.Health.readiness_checks())
      true

  """
  @spec readiness_checks() :: :ok | {:error, [{atom(), term()}]}
  def readiness_checks do
    failures =
      Enum.flat_map(
        [
          {:draining, &check_not_draining/0},
          {:storage, &check_storage/0},
          {:cache, &check_cache/0},
          {:listener_udp, &check_udp_listener/0}
        ],
        fn {name, check} ->
          case check.() do
            :ok -> []
            {:error, reason} -> [{name, reason}]
          end
        end
      )

    if failures == [], do: :ok, else: {:error, failures}
  end

  defp check_not_draining do
    if ExDns.Drain.draining?() do
      {:error, :draining}
    else
      :ok
    end
  end

  defp check_storage do
    try do
      ExDns.Storage.zones()
      :ok
    rescue
      reason -> {:error, reason}
    end
  end

  defp check_cache do
    try do
      _ = ExDns.Recursor.Cache.size()
      :ok
    rescue
      reason -> {:error, reason}
    end
  end

  defp check_udp_listener do
    case Process.whereis(Module.concat(ExDns.Listener.UDP, :inet)) do
      pid when is_pid(pid) -> :ok
      _ -> {:error, :listener_not_started}
    end
  end
end
