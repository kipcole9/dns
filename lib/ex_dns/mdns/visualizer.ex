defmodule ExDns.MDNS.Visualizer do
  @moduledoc """
  HTTP visualizer for the mDNS service registry observed on the local
  network.

  The page is a stateless render of the `ExDns.MDNS.Visualizer.Discoverer`
  GenServer's accumulated snapshot, with a `<meta http-equiv="refresh">`
  tag that re-fetches every 5 seconds. This mirrors the
  `Color.Palette.Visualizer` pattern: data layer in a single source of
  truth, HTTP layer reads it, rendering layer is pure.

  ## Routes

  * `GET /`          — main view (auto-refreshes every 5 s).
  * `GET /refresh`   — forces an immediate discovery cycle, then
    redirects to `/`.

  ## Standalone or mounted

  Run standalone with `ExDns.MDNS.Visualizer.Standalone.start(port: 4001)`,
  or mount in a Phoenix router via:

      forward "/mdns", ExDns.MDNS.Visualizer

  """

  use Plug.Router

  alias ExDns.MDNS.Visualizer.{Discoverer, Render}

  @refresh_seconds 5

  plug(:match)
  plug(:dispatch)

  get "/" do
    snapshot = Discoverer.snapshot()

    body =
      Render.page(
        "mDNS Services on the Local Network",
        Render.snapshot_view(snapshot),
        Render.refresh(@refresh_seconds)
      )

    conn
    |> put_resp_content_type("text/html")
    |> send_resp(200, body)
  end

  get "/refresh" do
    case Process.whereis(Discoverer) do
      nil -> :ok
      _ -> Discoverer.refresh_now()
    end

    conn
    |> put_resp_header("location", "/")
    |> send_resp(303, "")
  end

  match _ do
    send_resp(conn, 404, "not found")
  end
end
