defmodule ExDns.API.Router do
  @moduledoc """
  Plug.Router implementing the read-only `/api/v1/*` surface
  described in `priv/openapi/v1.yaml`.

  This module owns *only* the HTTP plumbing — request parsing,
  bearer-auth, status codes, JSON encoding. The actual data
  comes from `ExDns.API.Resources` (split out so the same
  data can be served from a CLI or test driver without going
  through HTTP).

  ## Mounting

  Bandit child spec is wired in `ExDns.Application` under the
  `:ex_dns, :api, [enabled: true, port: 9571]` config flag
  (defaults to off — operators opt in).
  """

  use Plug.Router

  alias ExDns.API.{Auth, Resources}
  alias ExDns.API.JSON, as: APIJSON

  plug(:match)
  plug(:dispatch_unauth)

  # ----- public probes (no bearer) ----------------------------------

  get "/api/v1/health" do
    send_resp(conn, 200, "ok\n")
  end

  get "/api/v1/ready" do
    case ExDns.Health.readiness_checks() do
      :ok -> send_resp(conn, 200, "ready\n")
      {:error, _failures} -> send_resp(conn, 503, "not ready\n")
    end
  end

  # ----- authenticated routes ---------------------------------------

  get "/api/v1/server" do
    conn |> auth() |> respond(200, Resources.server())
  end

  get "/api/v1/zones" do
    conn |> auth() |> respond(200, %{"zones" => Resources.zones()})
  end

  get "/api/v1/zones/:apex" do
    conn = auth(conn)

    case Resources.zone(apex) do
      nil -> respond(conn, 404, %{"error" => "zone not found"})
      zone -> respond(conn, 200, zone)
    end
  end

  get "/api/v1/zones/:apex/records" do
    conn = auth(conn)

    case Resources.zone(apex) do
      nil ->
        respond(conn, 404, %{"error" => "zone not found"})

      _zone ->
        params = fetch_query_params(conn).query_params
        opts = parse_record_options(params)
        %{records: records, total: total} = Resources.records(apex, opts)
        respond(conn, 200, %{"records" => records, "total" => total})
    end
  end

  get "/api/v1/secondaries/:apex" do
    conn = auth(conn)

    case Resources.secondary(apex) do
      nil -> respond(conn, 404, %{"error" => "no secondary for zone"})
      snapshot -> respond(conn, 200, snapshot)
    end
  end

  get "/api/v1/keys" do
    conn |> auth() |> respond(200, %{"keys" => Resources.keys()})
  end

  get "/api/v1/plugins" do
    conn |> auth() |> respond(200, %{"plugins" => Resources.plugins()})
  end

  get "/api/v1/events" do
    conn = auth(conn)

    if conn.halted do
      conn
    else
      ExDns.API.SSE.run(conn)
    end
  end

  get "/api/v1/metrics/summary" do
    conn = auth(conn)
    params = fetch_query_params(conn).query_params

    window =
      params
      |> Map.get("window_seconds", "60")
      |> parse_int(60)
      |> clamp(1, 3600)

    respond(conn, 200, Resources.metrics_summary(window))
  end

  # 404 fallback. Authenticate first so anonymous callers
  # cannot enumerate the surface — they always see 401, never
  # 404 distinguishing "not found" from "not allowed".
  match _ do
    conn = auth(conn)
    respond(conn, 404, %{"error" => "not found"})
  end

  # ----- middleware -------------------------------------------------

  # Probes don't need auth; everything else does. We split the
  # plug pipeline so the public probes work even without a
  # bearer token, while the rest run `Auth.call/2` lazily inside
  # each route via `auth/1` (so the 404 fallback also requires
  # auth — preventing route enumeration from unauthenticated
  # callers).
  defp dispatch_unauth(conn, _opts) do
    if probe_path?(conn.request_path) do
      __MODULE__.dispatch(conn, [])
    else
      __MODULE__.dispatch(conn, [])
    end
  end

  defp probe_path?("/api/v1/health"), do: true
  defp probe_path?("/api/v1/ready"), do: true
  defp probe_path?(_), do: false

  defp auth(conn) do
    Auth.call(conn, [])
  end

  defp respond(%Plug.Conn{halted: true} = conn, _status, _payload), do: conn

  defp respond(conn, status, payload) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, APIJSON.encode!(payload))
  end

  defp parse_record_options(params) do
    %{
      type: Map.get(params, "type"),
      name: Map.get(params, "name"),
      limit: Map.get(params, "limit", "200") |> parse_int(200) |> clamp(1, 1000),
      offset: Map.get(params, "offset", "0") |> parse_int(0) |> max(0)
    }
  end

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {n, ""} -> n
      _ -> default
    end
  end

  defp parse_int(_, default), do: default

  defp clamp(n, min_v, max_v), do: n |> max(min_v) |> min(max_v)
end
