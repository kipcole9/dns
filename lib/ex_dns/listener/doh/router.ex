defmodule ExDns.Listener.DoH.Router do
  @moduledoc """
  Plug implementing the `/dns-query` endpoint of RFC 8484.

  ## Methods

  * `POST /dns-query` with `Content-Type: application/dns-message`
    — body is the raw DNS query; response body is the raw DNS
    response with the same content type.

  * `GET  /dns-query?dns=<base64url-encoded-query>` (RFC 8484
    §4.1) — response body is the raw DNS response with content
    type `application/dns-message`.

  Other paths return 404; POST without
  `Content-Type: application/dns-message` returns 415; GET without
  a `dns` parameter or with one over 8 KiB returns 400.

  ## HTTP/2 and HTTP/3

  Negotiated transparently by Bandit when ALPN selects `h2` (over
  TLS); no per-request changes here. HTTP/3 is supported by Bandit
  and can be wired in `:ex_dns, :doh` once an operator configures
  the QUIC listener.

  ## Caching

  Successful responses carry `Cache-Control: max-age=N` per RFC
  8484 §5.1, where `N` is the minimum TTL of any record in the
  answer + authority sections. This lets intermediate HTTP caches
  serve repeat clients without bothering the resolver. Empty
  responses (NXDOMAIN with no SOA, NOTIMP, etc.) get a small fixed
  max-age.

  """

  @behaviour Plug

  import Plug.Conn

  alias ExDns.Message

  @content_type "application/dns-message"

  # 8 KiB ceiling on encoded GET-form messages. RFC 8484 §6 doesn't
  # mandate one but the practical limit is "what the longest URL
  # commonly survives end-to-end" — ~8 KiB is a safe baseline that
  # also bounds memory per request.
  @max_get_query_bytes 8 * 1024

  # Fallback Cache-Control for responses with no records in answer
  # or authority (NXDOMAIN-without-SOA, NOTIMP, etc.). A short
  # window so intermediate caches don't pin error responses
  # forever.
  @default_max_age 10

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
      %{"dns" => encoded} when byte_size(encoded) > @max_get_query_bytes ->
        send_resp(conn, 400, "dns parameter exceeds #{@max_get_query_bytes} bytes")

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
        request =
          ExDns.Request.new(query,
            source_ip: conn.remote_ip,
            source_port: nil,
            transport: :doh
          )

        start_metadata = query_metadata(query, conn.remote_ip)
        start_time = System.monotonic_time()

        :telemetry.execute(
          [:ex_dns, :query, :start],
          %{system_time: System.system_time()},
          start_metadata
        )

        raw_response = ExDns.resolver_module().resolve(request)

        response =
          raw_response
          |> then(&ExDns.Cookies.PostProcess.process(query, &1, conn.remote_ip))
          |> then(&ExDns.EDNSClientSubnet.PostProcess.process(query, &1))
          |> maybe_pad(query)

        response_bytes = Message.encode(response)

        :telemetry.execute(
          [:ex_dns, :query, :stop],
          %{duration: System.monotonic_time() - start_time},
          Map.merge(start_metadata, response_metadata(response))
        )

        conn
        |> put_resp_content_type(@content_type)
        |> put_resp_header("cache-control", "max-age=#{response_max_age(response)}")
        |> send_resp(200, response_bytes)

      {:error, _} ->
        send_resp(conn, 400, "could not decode DNS message")
    end
  end

  # Compute the value for Cache-Control: max-age based on the
  # smallest TTL across the response's answer + authority sections,
  # per RFC 8484 §5.1. Empty responses fall back to a small fixed
  # value so error responses don't get pinned in intermediate
  # caches.
  defp response_max_age(%Message{answer: answer, authority: authority}) do
    ttls =
      (answer ++ authority)
      |> Enum.map(&Map.get(&1, :ttl))
      |> Enum.filter(&is_integer/1)

    case ttls do
      [] -> @default_max_age
      _ -> Enum.min(ttls)
    end
  end

  defp response_max_age(_), do: @default_max_age

  defp query_metadata(%Message{question: %{host: host, type: type}}, remote_ip) do
    %{transport: :doh, qname: host, qtype: type, client: {remote_ip, nil}}
  end

  defp query_metadata(_, remote_ip) do
    %{transport: :doh, qname: nil, qtype: nil, client: {remote_ip, nil}}
  end

  defp response_metadata(%Message{header: %{rc: rcode, anc: anc}}) do
    %{rcode: rcode, answer_count: anc, validation: :none, cache: :none}
  end

  defp response_metadata(_) do
    %{rcode: nil, answer_count: 0, validation: :none, cache: :none}
  end

  defp maybe_pad(response, query) do
    if ExDns.EDNSPadding.requested?(query) do
      ExDns.EDNSPadding.pad(response)
    else
      response
    end
  end
end
