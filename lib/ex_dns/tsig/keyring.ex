defmodule ExDns.TSIG.Keyring do
  @moduledoc """
  Lookup table for TSIG shared secrets, keyed by key name.

  Two sources of keys, consulted in order:

  1. **Runtime store** — backed by
     `ExDns.TSIG.Keyring.Backend.configured/0`. Defaults to
     `ExDns.TSIG.Keyring.Backend.EKV`, so keys installed via
     `put/3` propagate across the cluster. Switch to
     `ExDns.TSIG.Keyring.Backend.ETS` for a process-local
     store with no cross-node propagation:

         config :ex_dns, :tsig_keyring,
           backend: ExDns.TSIG.Keyring.Backend.ETS

  2. **Static configuration** — keys declared under
     `Application.get_env(:ex_dns, :tsig_keys, %{...})` as a
     map shaped:

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

  Key names are compared case-insensitively per RFC 8945 §6
  (canonical owner names).

  """

  alias ExDns.TSIG.Keyring.Backend

  @doc "Initialises the configured runtime backend. Idempotent."
  @spec init() :: :ok
  def init do
    Backend.configured().init()
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

    case Backend.configured().lookup(key) do
      {:ok, entry} -> {:ok, entry}
      :error -> lookup_app_env(key)
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
  def put(name, algorithm, secret)
      when is_binary(name) and is_binary(algorithm) and is_binary(secret) do
    init()

    Backend.configured().put(
      normalize(name),
      %{algorithm: algorithm, secret: secret}
    )
  end

  @doc "Removes a previously-installed key from the runtime store."
  @spec delete(binary()) :: :ok
  def delete(name) when is_binary(name) do
    init()
    Backend.configured().delete(normalize(name))
  end

  @doc "Returns every key currently visible (runtime store + static config)."
  @spec all() :: [{binary(), %{algorithm: binary(), secret: binary()}}]
  def all do
    init()

    runtime = Backend.configured().all()

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
