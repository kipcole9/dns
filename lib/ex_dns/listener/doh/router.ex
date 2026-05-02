defmodule ExDns.Listener.DoH.Router do
  @moduledoc """
  Plug implementing the `/dns-query` endpoint of RFC 8484.

  Both POST and GET are supported. Other paths return 404; POST without
  `Content-Type: application/dns-message` returns 415; GET without a
  `dns` parameter returns 400.

  """

  @behaviour Plug

  import Plug.Conn

  alias ExDns.Message

  @content_type "application/dns-message"

  @impl Plug
  def init(options), do: options

  @impl Plug
  def call(%Plug.Conn{request_path: "/dns-query", method: "POST"} = conn, _options) do
    case get_req_header(conn, "content-type") do
      [type | _] -> if type_matches?(type), do: handle_post(conn), else: bad_content_type(conn)
      [] -> bad_content_type(conn)
    end
  end

  def call(%Plug.Conn{request_path: "/dns-query", method: "GET"} = conn, _options) do
    conn = fetch_query_params(conn)

    case conn.query_params do
      %{"dns" => encoded} ->
        case Base.url_decode64(encoded, padding: false) do
          {:ok, body} -> respond(conn, body)
          :error -> send_resp(conn, 400, "invalid base64url-encoded dns parameter")
        end

      _ ->
        send_resp(conn, 400, "missing dns query parameter")
    end
  end

  def call(conn, _options) do
    send_resp(conn, 404, "not found")
  end

  defp type_matches?(content_type) do
    content_type
    |> String.split(";", parts: 2)
    |> List.first()
    |> String.trim()
    |> Kernel.==(@content_type)
  end

  defp bad_content_type(conn) do
    send_resp(conn, 415, "expected Content-Type: #{@content_type}")
  end

  defp handle_post(conn) do
    {:ok, body, conn} = read_body(conn)
    respond(conn, body)
  end

  defp respond(conn, body) when is_binary(body) do
    case Message.decode(body) do
      {:ok, query} ->
        response = ExDns.resolver_module().resolve(query)
        response_bytes = Message.encode(response)

        conn
        |> put_resp_content_type(@content_type)
        |> send_resp(200, response_bytes)

      {:error, _} ->
        send_resp(conn, 400, "could not decode DNS message")
    end
  end
end
