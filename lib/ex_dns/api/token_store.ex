defmodule ExDns.API.TokenStore do
  @moduledoc """
  Persistent bearer-token registry for the `/api/v1` surface.

  Tokens are issued by `mix exdns.token.issue` and stored in a
  single file owned by the server (default
  `~/.config/exdns/tokens.json`, configurable via
  `:ex_dns, :api, [token_path: ...]`). The file is plain JSON so
  operators can audit it; it is `chmod 0600`.

  ## Token shape on disk

  ```
  %{
    "id" => binary,             # short opaque id, shown in audits
    "secret_hash" => binary,    # base64(SHA-256(secret))
    "role" => "viewer" | "zone_admin" | "cluster_admin",
    "scopes" => [zone_glob],    # ["*.internal.example", "ad.example"]
    "created_at_unix" => integer,
    "expires_at_unix" => integer | nil,
    "label" => binary | nil     # operator-supplied note
  }
  ```

  **Secrets at rest.** Only the SHA-256 hash of the secret is
  written to disk — the plaintext is shown to the operator
  exactly once, in the response of `issue/1`. A leaked
  `tokens.json` therefore exposes the metadata of every
  issued token but cannot be used to authenticate against the
  API. (Lost a secret? Issue a new one and revoke the old.)

  Existing v1 stores that contain a plaintext `"secret"` key
  are accepted on read and transparently re-hashed on the
  next `issue/1` or `revoke/1` write.

  ## Lookup

  `find_by_secret/1` hashes the presented bearer value and
  compares constant-time against every stored `secret_hash`.
  Returns the matching token record, or `:error` when nothing
  matches or the token has expired.
  """

  alias Plug.Crypto

  @cache_key {__MODULE__, :records_cache}

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

  The list is cached in `:persistent_term` keyed by the token
  file's mtime, so the steady-state cost of an authenticated
  request is one `File.stat/1` rather than a full file read +
  JSON decode. The cache invalidates automatically when an
  external editor (or another node sharing the path) bumps the
  file's mtime.
  """
  @spec all() :: [map()]
  def all do
    file = path()

    case File.stat(file, time: :posix) do
      {:ok, %File.Stat{mtime: mtime, size: size}} ->
        cached_for(file, {mtime, size}, &read_from_disk/1)

      {:error, :enoent} ->
        []

      {:error, _} ->
        []
    end
  end

  defp cached_for(file, key, miss_fun) do
    case :persistent_term.get(@cache_key, :none) do
      {^file, ^key, records} ->
        records

      _ ->
        records = miss_fun.(file)
        :persistent_term.put(@cache_key, {file, key, records})
        records
    end
  end

  defp read_from_disk(file) do
    case File.read(file) do
      {:ok, bin} -> decode!(bin)
      _ -> []
    end
  end

  defp invalidate_cache do
    :persistent_term.erase(@cache_key)
    :ok
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

    secret = generate_secret()

    persisted = %{
      "id" => generate_id(),
      "secret_hash" => hash_secret(secret),
      "role" => to_string(role),
      "scopes" => Enum.map(scopes, &to_string/1),
      "created_at_unix" => System.os_time(:second),
      "expires_at_unix" => expires_at_unix,
      "label" => label
    }

    write_all([persisted | all()])

    # Caller (the mix task) gets the plaintext secret exactly
    # once. The disk file holds only `secret_hash`.
    {:ok, Map.put(persisted, "secret", secret)}
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
    presented_hash = hash_secret(secret)

    Enum.reduce_while(all(), :error, fn record, acc ->
      stored_hash = stored_secret_hash(record, secret)

      cond do
        is_nil(stored_hash) ->
          {:cont, acc}

        Crypto.secure_compare(stored_hash, presented_hash) ->
          if expired?(record, now),
            do: {:halt, :error},
            else: {:halt, {:ok, record}}

        true ->
          {:cont, acc}
      end
    end)
  end

  # New records carry `"secret_hash"`. Records written by an
  # earlier release may still carry plaintext `"secret"` —
  # accept them for one more lookup so existing operators
  # don't lock themselves out, and rely on the next
  # `issue/1` / `revoke/1` to rewrite the file in the new
  # shape.
  defp stored_secret_hash(%{"secret_hash" => stored}, _presented) when is_binary(stored) do
    stored
  end

  defp stored_secret_hash(%{"secret" => legacy_plaintext}, _presented)
       when is_binary(legacy_plaintext) do
    hash_secret(legacy_plaintext)
  end

  defp stored_secret_hash(_, _), do: nil

  defp expired?(%{"expires_at_unix" => nil}, _now), do: false
  defp expired?(%{"expires_at_unix" => exp}, now) when is_integer(exp), do: exp <= now
  defp expired?(_, _), do: false

  defp write_all(records) do
    bin = records |> Enum.map(&migrate_legacy_record/1) |> encode!()
    File.mkdir_p!(Path.dirname(path()))
    File.write!(path(), bin)
    File.chmod(path(), 0o600)
    invalidate_cache()
    :ok
  end

  # Records written by an earlier release carried plaintext
  # `"secret"`. Every persisted-record write goes through this
  # so the legacy field is dropped + replaced by the hash on
  # any mutation (issue / revoke). After one mutation the file
  # contains no plaintext secrets at all.
  defp migrate_legacy_record(%{"secret_hash" => _} = record), do: Map.delete(record, "secret")

  defp migrate_legacy_record(%{"secret" => secret} = record) when is_binary(secret) do
    record
    |> Map.put("secret_hash", hash_secret(secret))
    |> Map.delete("secret")
  end

  defp migrate_legacy_record(record), do: record

  defp generate_id do
    :crypto.strong_rand_bytes(6) |> Base.url_encode64(padding: false)
  end

  defp generate_secret do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  defp hash_secret(secret) when is_binary(secret) do
    :crypto.hash(:sha256, secret) |> Base.encode64(padding: false)
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
