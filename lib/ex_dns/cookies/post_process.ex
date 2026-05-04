defmodule ExDns.Cookies.PostProcess do
  @moduledoc """
  Listener-layer hook that handles RFC 7873 DNS Cookies after the
  resolver has produced its response.

  The resolver itself is purely functional over `%ExDns.Message{}`
  and intentionally has no notion of source IP. This module sits
  between the resolver and the wire encoder: given the inbound
  request (which carries the source-IP context) and the resolver's
  response, it inspects the COOKIE option, validates or generates a
  server cookie, and writes the resulting COOKIE option back into
  the response's OPT pseudo-RR.

  ## Behaviour

  | Inbound state              | Action                                                         |
  |----------------------------|----------------------------------------------------------------|
  | No COOKIE option           | Pass through unchanged.                                        |
  | Client-only cookie (8 B)   | Compute a fresh server cookie; embed in response OPT.          |
  | Client + valid server      | Echo the same client cookie + a refreshed server cookie.       |
  | Client + invalid server    | If `:enforce` is true, set rcode to BADCOOKIE (23); else echo a fresh server cookie. |

  ## Wiring

  Called from `ExDns.Resolver.Worker` after `resolver.resolve/1`
  returns. Off when `:ex_dns, :cookies, [enabled: false]` is set.
  """

  alias ExDns.Cookies
  alias ExDns.Message
  alias ExDns.Resource.OPT

  # RFC 7873 §6: extended rcode 23 = BADCOOKIE.
  @badcookie 23

  @doc """
  Process DNS Cookies on the response.

  ### Arguments

  * `query` — the original `%ExDns.Message{}` as decoded from the
    wire.

  * `response` — the resolver's reply `%ExDns.Message{}`.

  * `client_ip` — the source-address tuple of the request.

  ### Returns

  * The (possibly modified) response message.

  ### Examples

      iex> alias ExDns.Message
      iex> alias ExDns.Message.{Header, Question}
      iex> empty_header = %Header{id: 0, qr: 0, oc: 0, aa: 0, tc: 0, rd: 0, ra: 0,
      ...>                         ad: 0, cd: 0, rc: 0, qc: 1, anc: 0, auc: 0, adc: 0}
      iex> q = %Message{header: empty_header,
      ...>              question: %Question{host: "x", type: :a, class: :in},
      ...>              answer: [], authority: [], additional: []}
      iex> ExDns.Cookies.PostProcess.process(q, %{q | header: %{empty_header | qr: 1}}, {127, 0, 0, 1})
      ...> |> Map.get(:additional)
      []

  """
  @spec process(Message.t(), Message.t(), tuple()) :: Message.t()
  def process(%Message{} = query, %Message{} = response, client_ip) do
    if cookies_enabled?() do
      do_process(query, response, client_ip)
    else
      response
    end
  end

  defp cookies_enabled? do
    case Application.get_env(:ex_dns, :cookies) do
      nil -> false
      options when is_list(options) -> Keyword.get(options, :enabled, false)
      _ -> false
    end
  end

  defp enforce? do
    Application.get_env(:ex_dns, :cookies, []) |> Keyword.get(:enforce, false)
  end

  defp do_process(query, response, client_ip) do
    case query_cookie(query) do
      :none ->
        response

      {:error, :malformed} ->
        # Malformed COOKIE option: per RFC 7873 §5.2.2, treat as
        # FORMERR. We attach no cookie option.
        rewrite_rcode(response, 1)

      {:ok, client_cookie, nil} ->
        attach_server_cookie(response, client_cookie, client_ip)

      {:ok, client_cookie, server_cookie} ->
        case Cookies.verify(client_cookie, server_cookie, client_ip) do
          :ok ->
            # Valid cookie — echo a freshly-minted one so the client
            # has a current timestamp.
            attach_server_cookie(response, client_cookie, client_ip)

          {:error, _reason} ->
            if enforce?() do
              response
              |> rewrite_rcode(@badcookie)
              |> attach_server_cookie(client_cookie, client_ip)
            else
              attach_server_cookie(response, client_cookie, client_ip)
            end
        end
    end
  end

  defp query_cookie(%Message{additional: additional}) when is_list(additional) do
    case Enum.find(additional, &match?(%OPT{}, &1)) do
      %OPT{options: options} -> Cookies.find_in_options(options)
      _ -> :none
    end
  end

  defp query_cookie(_), do: :none

  # Build a fresh server cookie and merge a COOKIE option into the
  # response's OPT additional record. If the response has no OPT
  # (legacy client did not advertise EDNS0 — but somehow had a
  # cookie?), we add one.
  defp attach_server_cookie(%Message{additional: additional} = response, client_cookie, client_ip) do
    server_cookie = Cookies.make_server_cookie(client_cookie, client_ip)
    cookie_option = Cookies.encode_option(client_cookie, server_cookie)

    new_additional =
      case Enum.split_with(additional, &match?(%OPT{}, &1)) do
        {[], rest} ->
          rest ++ [%OPT{payload_size: 1232, options: [cookie_option]}]

        {[%OPT{options: options} = opt | _], rest} ->
          new_opt = %OPT{opt | options: replace_cookie(options, cookie_option)}
          rest ++ [new_opt]
      end

    %Message{response | additional: new_additional, header: bump_adc(response.header, new_additional)}
  end

  defp replace_cookie(options, {code, _} = new_option) do
    [new_option | List.keydelete(options, code, 0)]
  end

  defp rewrite_rcode(%Message{header: header} = response, rcode) do
    %Message{response | header: %{header | rc: rcode}}
  end

  defp bump_adc(header, additional) do
    %{header | adc: length(additional)}
  end
end
