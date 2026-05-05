defmodule ExDns.API.SSE do
  @moduledoc """
  Server-Sent Events handler for `GET /api/v1/events`.

  ## Behaviour

  After auth has run, the handler:

  1. Writes the response headers + opens a chunked body.
  2. Subscribes itself to the `ExDns.API.Events` broker.
  3. Pumps `{:exdns_event, type, payload}` messages to the
     client as SSE frames.
  4. Periodically emits a comment (`": keepalive\\n\\n"`) so
     intermediate proxies don't time out the connection.
  5. Returns when the client disconnects (chunk write fails).

  ## Wire format

  Each event:

  ```
  event: <type>
  data: <json>

  ```

  Plus an initial comment frame so the client knows the stream
  is alive even before the first real event arrives.
  """

  alias ExDns.API.Events

  @keepalive_ms 15_000

  @doc """
  Run the SSE loop on `conn`. Blocks until the client
  disconnects, then returns the (now-closed) conn.
  """
  @spec run(Plug.Conn.t()) :: Plug.Conn.t()
  def run(conn) do
    # Best-effort: the broker may not be running in test
    # environments that don't bring up the API supervisor —
    # the route still works, it just never delivers events.
    if Process.whereis(Events), do: Events.subscribe(self())

    conn =
      conn
      |> Plug.Conn.put_resp_header("content-type", "text/event-stream")
      |> Plug.Conn.put_resp_header("cache-control", "no-cache")
      |> Plug.Conn.put_resp_header("connection", "keep-alive")
      |> Plug.Conn.send_chunked(200)

    case Plug.Conn.chunk(conn, ": ok\n\n") do
      {:ok, conn} -> loop(conn)
      {:error, _} -> conn
    end
  end

  defp loop(conn) do
    timer = Process.send_after(self(), :keepalive, @keepalive_ms)

    receive do
      {:exdns_event, type, payload} ->
        Process.cancel_timer(timer)
        frame = Events.render_sse(type, payload)

        case Plug.Conn.chunk(conn, frame) do
          {:ok, conn} -> loop(conn)
          {:error, _} -> conn
        end

      :keepalive ->
        case Plug.Conn.chunk(conn, ": keepalive\n\n") do
          {:ok, conn} -> loop(conn)
          {:error, _} -> conn
        end
    end
  end
end
