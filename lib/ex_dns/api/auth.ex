defmodule ExDns.API.Auth do
  @moduledoc """
  Bearer-token authentication + role-based authorisation plug
  for the `/api/v1` surface.

  ## Behaviour

  Every request must carry `Authorization: Bearer <token>`. The
  presented token is looked up via `ExDns.API.TokenStore`. On
  success the token's role + scopes are stashed in
  `conn.assigns[:exdns_token]` so route handlers can branch on
  capability without re-running auth.

  Routes that need more than read access call
  `require_role/2` and `require_scope/2` to assert the
  capability they need; failures emit `403 forbidden`.

  ## Roles

  * `viewer` — read-only on every endpoint.
  * `zone_admin` — read + record/zone-level mutation, scoped
    by zone-name globs the token was issued for.
  * `cluster_admin` — full surface, no scope restriction.
  """

  import Plug.Conn

  alias ExDns.API.TokenStore

  @doc false
  def init(options), do: options

  @doc false
  def call(conn, _options) do
    case extract_bearer(conn) do
      {:ok, secret} ->
        case TokenStore.find_by_secret(secret) do
          {:ok, token} -> assign(conn, :exdns_token, token)
          :error -> deny(conn, 401, "unauthorized")
        end

      :error ->
        deny(conn, 401, "unauthorized")
    end
  end

  @doc """
  Halt the request with `403 forbidden` when the assigned token
  doesn't carry `required_role` (or higher).

  Role hierarchy: `cluster_admin > zone_admin > viewer`.
  """
  @spec require_role(Plug.Conn.t(), atom() | binary()) :: Plug.Conn.t()
  def require_role(%Plug.Conn{halted: true} = conn, _), do: conn

  def require_role(conn, required_role) do
    if has_role?(conn.assigns[:exdns_token], required_role) do
      conn
    else
      deny(conn, 403, "forbidden: role")
    end
  end

  @doc """
  Halt the request with `403 forbidden` when the assigned token
  is scoped and `zone` doesn't match any of its scope globs.
  An empty scope list means "all zones".
  """
  @spec require_scope(Plug.Conn.t(), binary()) :: Plug.Conn.t()
  def require_scope(%Plug.Conn{halted: true} = conn, _), do: conn

  def require_scope(conn, zone) when is_binary(zone) do
    token = conn.assigns[:exdns_token] || %{}

    if scope_allows?(token, zone) do
      conn
    else
      deny(conn, 403, "forbidden: scope")
    end
  end

  # ----- predicates --------------------------------------------------

  @doc false
  def has_role?(nil, _required), do: false

  def has_role?(token, required) do
    rank(token["role"]) >= rank(to_string(required))
  end

  defp rank("cluster_admin"), do: 3
  defp rank("zone_admin"), do: 2
  defp rank("viewer"), do: 1
  defp rank(_), do: 0

  @doc false
  def scope_allows?(%{"role" => "cluster_admin"}, _zone), do: true
  def scope_allows?(%{"scopes" => []}, _zone), do: true

  def scope_allows?(%{"scopes" => globs}, zone) when is_list(globs) do
    norm = normalize(zone)
    Enum.any?(globs, fn glob -> matches?(norm, normalize(glob)) end)
  end

  def scope_allows?(_, _), do: false

  # ----- helpers -----------------------------------------------------

  defp extract_bearer(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> secret] -> {:ok, secret}
      ["bearer " <> secret] -> {:ok, secret}
      _ -> :error
    end
  end

  defp deny(conn, status, message) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, json_encode!(%{error: message}))
    |> halt()
  end

  defp json_encode!(term) do
    term |> :json.encode() |> IO.iodata_to_binary()
  end

  defp normalize(name) do
    name |> to_string() |> String.trim_trailing(".") |> String.downcase(:ascii)
  end

  defp matches?(name, "*." <> suffix), do: String.ends_with?(name, "." <> suffix) or name == suffix
  defp matches?(name, glob), do: name == glob
end
