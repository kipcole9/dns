defmodule ExDns.Admin do
  @moduledoc """
  Operator-facing HTTP API for runtime control.

  ## Endpoints

  * `GET  /admin/zones` — list every loaded zone with its current
    SOA serial.

  * `POST /admin/zones/reload` — re-read every file in
    `:ex_dns, :zones`. Returns `{loaded, failed}` counts.

  * `POST /admin/zones/:apex/notify` — trigger an immediate
    refresh on the secondary-zone manager for `:apex`. 404 when
    that apex isn't a configured secondary.

  * `GET  /admin/secondaries/:apex` — return the secondary state
    machine's current state (`:initial` | `:loaded`) and SOA
    serial for `:apex`. 404 when no secondary is configured.

  * `GET  /healthz` and `/readyz` — proxied through to
    `ExDns.Health` so a single bind point covers both ops
    surfaces.

  ## Security

  This API exposes operational control. Two safeguards are
  applied:

  1. The listener binds to `127.0.0.1` by default. Override via
     `:ex_dns, :admin, [bind: {0, 0, 0, 0}]` only when fronted by
     a TLS proxy or in a private network.

  2. When `:ex_dns, :admin, [bearer_token: "..."]` is set, every
     request must carry `Authorization: Bearer <token>`. Off by
     default; recommended for any non-loopback bind.

  ## Configuration

      config :ex_dns, :admin,
        enabled: true,
        port: 9570,
        bearer_token: System.fetch_env!("EXDNS_ADMIN_TOKEN")

  Off by default — opt-in via `enabled: true`.
  """

  use Plug.Router

  alias ExDns.Resource.SOA
  alias ExDns.Storage
  alias ExDns.Zone.{Reload, Secondary}

  plug(:authenticate)
  plug(:match)
  plug(:dispatch)

  # ----- routes ----------------------------------------------------

  get "/admin/zones" do
    payload = %{
      zones:
        Storage.zones()
        |> Enum.map(fn apex ->
          %{
            apex: apex,
            serial: serial_for(apex)
          }
        end)
    }

    json(conn, 200, payload)
  end

  post "/admin/zones/reload" do
    {loaded, failed} = Reload.reload_all()
    json(conn, 200, %{loaded: loaded, failed: failed})
  end

  post "/admin/zones/:apex/notify" do
    case Secondary.notify(apex) do
      :ok -> json(conn, 200, %{apex: apex, triggered: true})
      {:error, :no_secondary_for_zone} -> json(conn, 404, %{error: "no secondary for zone"})
    end
  end

  get "/admin/secondaries/:apex" do
    case Secondary.snapshot(apex) do
      nil ->
        json(conn, 404, %{error: "no secondary for zone"})

      {state, data} ->
        json(conn, 200, %{
          apex: apex,
          state: state,
          serial: serial_or_nil(data.soa),
          last_success_unix: last_success_unix(data),
          tsig_key: data.tsig_key
        })
    end
  end

  get "/healthz" do
    send_resp(conn, 200, "ok\n")
  end

  get "/readyz" do
    case ExDns.Health.readiness_checks() do
      :ok ->
        send_resp(conn, 200, "ready\n")

      {:error, failures} ->
        send_resp(conn, 503, format_failures(failures))
    end
  end

  match _ do
    json(conn, 404, %{error: "not found"})
  end

  # ----- middleware ------------------------------------------------

  defp authenticate(conn, _opts) do
    case Application.get_env(:ex_dns, :admin, []) |> Keyword.get(:bearer_token) do
      nil ->
        # No token configured → no authentication required (assumed
        # behind a localhost bind or TLS proxy enforcing identity).
        conn

      token when is_binary(token) ->
        case get_req_header(conn, "authorization") do
          ["Bearer " <> presented] when presented == token ->
            conn

          _ ->
            conn
            |> put_resp_content_type("application/json")
            |> send_resp(401, json_encode!(%{error: "unauthorized"}))
            |> halt()
        end
    end
  end

  # ----- helpers ---------------------------------------------------

  defp json(conn, status, payload) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, json_encode!(payload))
  end

  # Wrap the built-in `:json.encode/1` so we always emit a binary
  # rather than the iodata it natively returns.
  defp json_encode!(term) do
    term |> :json.encode() |> IO.iodata_to_binary()
  end

  defp serial_for(apex) do
    case Storage.lookup(apex, :soa) do
      {:ok, _, [%SOA{serial: serial} | _]} -> serial
      _ -> nil
    end
  end

  defp serial_or_nil(%SOA{serial: serial}), do: serial
  defp serial_or_nil(_), do: nil

  defp last_success_unix(%{last_success: nil}), do: nil

  defp last_success_unix(%{last_success: monotonic}) when is_integer(monotonic) do
    # Convert monotonic seconds to wall-clock unix seconds for the
    # operator's UI. Approximation: now_wall - (now_monotonic - last).
    now_mono = System.monotonic_time(:second)
    now_wall = System.os_time(:second)
    now_wall - (now_mono - monotonic)
  end

  defp format_failures(failures) do
    body =
      ["not ready" | Enum.map(failures, fn {name, reason} -> "#{name}: #{inspect(reason)}" end)]
      |> Enum.join("\n")

    body <> "\n"
  end
end
