defmodule ExDns.Listener.DoH do
  @moduledoc """
  DNS over HTTPS (DoH) listener (RFC 8484).

  Built on `Bandit` + `Plug` (which run over `ThousandIsland`). Exposes
  the `/dns-query` endpoint per RFC 8484 §4.1:

  * `POST /dns-query` with `Content-Type: application/dns-message` —
    body is the raw DNS query bytes; response body is the raw DNS
    response bytes with the same content type.

  * `GET /dns-query?dns=<base64url-encoded-query>` — response is the
    same `application/dns-message` body.

  ## Configuration

  Listening is opt-in. Add this to your `config/runtime.exs` to bind a
  DoH listener:

      config :ex_dns, doh: [scheme: :http, port: 8080]

  When `:doh` is unset, the listener is not started.

  This implementation runs plain HTTP. For real-world DoH you should
  put it behind a TLS-terminating proxy or pass `scheme: :https,
  certfile: …, keyfile: …` to Bandit.

  """

  @doc """
  Returns the child spec used by the application supervisor when
  `:ex_dns, :doh` is configured.
  """
  def child_spec(options) do
    options =
      options
      |> Keyword.put_new(:scheme, :http)
      |> Keyword.put_new(:port, 8080)
      |> Keyword.put(:plug, ExDns.Listener.DoH.Router)

    Bandit.child_spec(options)
  end
end
