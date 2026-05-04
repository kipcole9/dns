defmodule ExDns.TSIG.Keyring do
  @moduledoc """
  Lookup table for TSIG shared secrets, keyed by key name.

  Keys live under `Application.get_env(:ex_dns, :tsig_keys, %{...})`
  as a map shaped:

      %{
        "transfer.example." => %{
          algorithm: "hmac-sha256.",
          secret: <<…raw bytes…>>
        },
        "ddns.example." => %{
          algorithm: "hmac-sha256.",
          # Secrets in config files are typically base64-encoded; the
          # accessor decodes them transparently.
          secret_base64: "MGZmMzNjY2RkY2NkY2NkZGNjY2RkY2NkY2RjZA=="
        }
      }

  Tests and runtime code can also call `put/3` to install a key
  programmatically.

  Key names are compared case-insensitively per RFC 8945 §6
  (canonical owner names).

  """

  @table :ex_dns_tsig_keys

  @doc "Initialises the in-process keyring table. Idempotent."
  @spec init() :: :ok
  def init do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [
          :set,
          :public,
          :named_table,
          read_concurrency: true,
          write_concurrency: true
        ])

        :ok

      _ ->
        :ok
    end
  end

  @doc """
  Looks up a key by its name.

  ### Returns

  * `{:ok, %{algorithm: name, secret: binary}}` when the key is configured.
  * `:error` otherwise.
  """
  @spec lookup(binary()) ::
          {:ok, %{algorithm: binary(), secret: binary()}} | :error
  def lookup(name) when is_binary(name) do
    init()
    key = normalize(name)

    case :ets.lookup(@table, key) do
      [{^key, value}] -> {:ok, value}
      [] -> lookup_app_env(key)
    end
  end

  defp lookup_app_env(name) do
    keys = Application.get_env(:ex_dns, :tsig_keys, %{})

    Enum.find_value(keys, :error, fn {key_name, key_value} ->
      if normalize(key_name) == name do
        {:ok, materialise(key_value)}
      end
    end)
  end

  defp materialise(%{secret: secret} = entry) when is_binary(secret) do
    %{algorithm: Map.get(entry, :algorithm, "hmac-sha256."), secret: secret}
  end

  defp materialise(%{secret_base64: encoded} = entry) when is_binary(encoded) do
    %{
      algorithm: Map.get(entry, :algorithm, "hmac-sha256."),
      secret: Base.decode64!(encoded)
    }
  end

  @doc """
  Installs a key programmatically. Useful for tests and short-lived
  registrations.
  """
  @spec put(binary(), binary(), binary()) :: :ok
  def put(name, algorithm, secret) when is_binary(name) and is_binary(secret) do
    init()
    :ets.insert(@table, {normalize(name), %{algorithm: algorithm, secret: secret}})
    :ok
  end

  @doc "Removes a previously-installed key."
  @spec delete(binary()) :: :ok
  def delete(name) when is_binary(name) do
    init()
    :ets.delete(@table, normalize(name))
    :ok
  end

  @doc "Returns every key currently in the table (programmatic + config)."
  @spec all() :: [{binary(), %{algorithm: binary(), secret: binary()}}]
  def all do
    init()

    runtime = :ets.tab2list(@table)

    config =
      Application.get_env(:ex_dns, :tsig_keys, %{})
      |> Enum.map(fn {name, value} -> {normalize(name), materialise(value)} end)

    Enum.uniq_by(runtime ++ config, fn {name, _} -> name end)
  end

  @doc false
  def normalize(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end
end
