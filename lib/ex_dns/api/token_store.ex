defmodule ExDns.API.TokenStore do
  @moduledoc """
  Persistent bearer-token registry for the `/api/v1` surface.

  Tokens are issued by `mix exdns.token.issue` and stored in a
  single file owned by the server (default
  `~/.config/exdns/tokens.json`, configurable via
  `:ex_dns, :api, [token_path: ...]`). The file is plain JSON so
  operators can audit it; it should be `chmod 0600`.

  ## Token shape

  ```
  %{
    "id" => binary,            # short opaque id, shown in audits
    "secret" => binary,        # the actual bearer value (32+ bytes hex)
    "role" => "viewer" | "zone_admin" | "cluster_admin",
    "scopes" => [zone_glob],   # ["*.internal.example", "ad.example"]
    "created_at_unix" => integer,
    "expires_at_unix" => integer | nil,
    "label" => binary | nil    # operator-supplied note
  }
  ```

  ## Lookup

  `find_by_secret/1` returns the token record (sans secret) for
  the value the client presented in `Authorization: Bearer …`,
  or `:error` when nothing matches or the token is expired.

  Lookup is constant-time per token (compares with `Plug.Crypto`'s
  `secure_compare/2`) to avoid timing leaks.
  """

  alias Plug.Crypto

  @doc "Path the store reads + writes."
  @spec path() :: Path.t()
  def path do
    Application.get_env(:ex_dns, :api, [])
    |> Keyword.get(:token_path, default_path())
  end

  defp default_path do
    Path.join(:filename.basedir(:user_config, "exdns"), "tokens.json")
  end

  @doc """
  Read every token from disk. Returns `[]` when the file does
  not exist.
  """
  @spec all() :: [map()]
  def all do
    case File.read(path()) do
      {:ok, bin} -> decode!(bin)
      {:error, :enoent} -> []
      {:error, _} -> []
    end
  end

  @doc """
  Insert a new token. Returns the full record (including the
  generated `secret`) so the caller can show it to the operator
  exactly once.

  ### Arguments

  * `attributes` is a map with at least `:role` and `:scopes`.
    `:label` is optional. `:expires_at_unix` is optional;
    `nil` means no expiry.
  """
  @spec issue(map()) :: {:ok, map()} | {:error, term()}
  def issue(attributes) when is_map(attributes) do
    role = Map.fetch!(attributes, :role)
    scopes = Map.get(attributes, :scopes, [])
    label = Map.get(attributes, :label)
    expires_at_unix = Map.get(attributes, :expires_at_unix)

    record = %{
      "id" => generate_id(),
      "secret" => generate_secret(),
      "role" => to_string(role),
      "scopes" => Enum.map(scopes, &to_string/1),
      "created_at_unix" => System.os_time(:second),
      "expires_at_unix" => expires_at_unix,
      "label" => label
    }

    write_all([record | all()])
    {:ok, record}
  end

  @doc """
  Revoke a token by its `id`. Returns `:ok` whether or not the
  id existed (idempotent).
  """
  @spec revoke(binary()) :: :ok
  def revoke(id) when is_binary(id) do
    remaining = Enum.reject(all(), fn r -> Map.fetch!(r, "id") == id end)
    write_all(remaining)
    :ok
  end

  @doc """
  Look up a token by its presented secret value. Performs a
  constant-time comparison against every stored secret to
  avoid timing oracles.

  ### Returns

  * `{:ok, token}` — token record (still includes the secret;
    the caller is the auth plug).
  * `:error` — no match, or the matched token has expired.
  """
  @spec find_by_secret(binary()) :: {:ok, map()} | :error
  def find_by_secret(secret) when is_binary(secret) do
    now = System.os_time(:second)

    Enum.reduce_while(all(), :error, fn record, acc ->
      stored = Map.fetch!(record, "secret")

      if Crypto.secure_compare(stored, secret) do
        if expired?(record, now), do: {:halt, :error}, else: {:halt, {:ok, record}}
      else
        {:cont, acc}
      end
    end)
  end

  defp expired?(%{"expires_at_unix" => nil}, _now), do: false
  defp expired?(%{"expires_at_unix" => exp}, now) when is_integer(exp), do: exp <= now
  defp expired?(_, _), do: false

  defp write_all(records) do
    bin = encode!(records)
    File.mkdir_p!(Path.dirname(path()))
    File.write!(path(), bin)
    File.chmod(path(), 0o600)
    :ok
  end

  defp generate_id do
    :crypto.strong_rand_bytes(6) |> Base.url_encode64(padding: false)
  end

  defp generate_secret do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  defp encode!(term) do
    term |> :json.encode() |> IO.iodata_to_binary()
  end

  defp decode!(bin) do
    case :json.decode(bin) do
      list when is_list(list) -> list
      _ -> []
    end
  end
end
