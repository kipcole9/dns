defmodule ExDns.BlackHole.Lists.Fetcher do
  @moduledoc """
  HTTP client for blocklist fetches with conditional-GET
  support.

  Each fetch sends `If-Modified-Since` (when we have a
  recorded `last_modified`) and `If-None-Match` (when we have
  a recorded `etag`). A 304 response returns
  `{:not_modified, validators}` so the subscriber can bump
  its `last_refresh` timestamp without re-parsing the body.

  ## Returns

  * `{:ok, %{body: binary, etag: binary | nil, last_modified:
    binary | nil}}` on a 200.
  * `{:not_modified, %{etag: …, last_modified: …}}` on a 304.
  * `{:error, reason}` on transport / 4xx / 5xx.
  """

  @type validators :: %{etag: binary() | nil, last_modified: binary() | nil}

  @doc "Fetch `url` with optional conditional-GET headers."
  @spec fetch(binary(), keyword()) ::
          {:ok, %{body: binary(), etag: binary() | nil, last_modified: binary() | nil}}
          | {:not_modified, validators()}
          | {:error, term()}
  def fetch(url, options \\ []) when is_binary(url) do
    headers = build_headers(options)
    req_options = Keyword.get(options, :req_options, [])

    case Req.request(
           [
             method: :get,
             url: url,
             headers: headers,
             receive_timeout: Keyword.get(options, :timeout_ms, 30_000),
             retry: false
           ] ++ req_options
         ) do
      {:ok, %Req.Response{status: 200} = resp} ->
        {:ok,
         %{
           body: ensure_binary(resp.body),
           etag: header(resp, "etag"),
           last_modified: header(resp, "last-modified")
         }}

      {:ok, %Req.Response{status: 304} = resp} ->
        {:not_modified,
         %{
           etag: header(resp, "etag"),
           last_modified: header(resp, "last-modified")
         }}

      {:ok, %Req.Response{status: status, body: body}} ->
        {:error, {:status, status, ensure_binary(body)}}

      {:error, reason} ->
        {:error, {:transport, reason}}
    end
  end

  defp build_headers(options) do
    base = [{"accept", "text/plain, */*"}, {"user-agent", "ExDns-BlackHole/0.1"}]

    base
    |> add_header("if-none-match", Keyword.get(options, :etag))
    |> add_header("if-modified-since", Keyword.get(options, :last_modified))
  end

  defp add_header(headers, _key, nil), do: headers
  defp add_header(headers, _key, ""), do: headers
  defp add_header(headers, key, value), do: [{key, value} | headers]

  defp header(%Req.Response{headers: headers}, key) when is_map(headers) do
    case Map.get(headers, key) do
      [v | _] -> v
      v when is_binary(v) -> v
      _ -> nil
    end
  end

  defp header(_, _), do: nil

  defp ensure_binary(body) when is_binary(body), do: body
  defp ensure_binary(other), do: to_string(other)
end
