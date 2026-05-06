defmodule ExDns.Bootstrap do
  @moduledoc """
  Single-use bootstrap code consumed by the first-run UI
  wizard.

  ## The problem this solves

  Every prior on-ramp for ExDns required the operator to
  type a Mix command (`mix exdns.token.issue`) before the
  Web UI could be used at all. That's fine for developers,
  fatal for pi-hole-class users.

  The fix:

  * The installer (`contrib/install/install.sh`) drops a
    cryptographically-strong random code into
    `:ex_dns, :bootstrap, [code_path: ...]` (default
    `/var/lib/exdns/bootstrap.code`) with mode 0600 owned
    by the `exdns` user.

  * The installer prints the code on success and the
    operator types or pastes it into the wizard at
    `/setup` in the Web UI.

  * `consume/1` validates the code against the file
    contents constant-time, deletes the file, issues a
    fresh `cluster_admin` API token (returned to the
    caller exactly once), and closes the bootstrap
    window for good.

  ## Why a file, not an env var

  An env var leaks into `ps`, into systemd's per-unit
  status output, and into any child process. A 0600 file
  on the same host is the lowest-friction transport that
  doesn't expand the disclosure surface.

  ## Configuration

      config :ex_dns, :bootstrap,
        enabled: true,
        code_path: "/var/lib/exdns/bootstrap.code"

  Set `enabled: false` after first use, or just delete
  the file — the module treats absence as "no bootstrap
  pending".
  """

  alias ExDns.API.TokenStore
  alias Plug.Crypto

  @default_path "/var/lib/exdns/bootstrap.code"

  @doc """
  Whether a bootstrap code is currently pending — i.e. a
  readable file exists at the configured path. The setup
  wizard checks this before deciding to render its
  on-screen flow.
  """
  @spec pending?() :: boolean()
  def pending? do
    enabled?() and File.regular?(path())
  end

  @doc """
  Validate the operator-supplied `presented` code against
  the on-disk bootstrap code (constant-time compare). On
  success: delete the bootstrap file, issue a single
  `cluster_admin` API token, return it. On failure:
  return `:error`.

  Single-use: a successful `consume/1` removes the file,
  so a second call returns `:error`.

  ### Returns

  * `{:ok, %{"id" => ..., "secret" => ..., "role" => "cluster_admin", ...}}`
    on success — same shape as `TokenStore.issue/1`.

  * `{:error, :not_pending}` — no bootstrap file present.

  * `{:error, :invalid_code}` — file exists but the
    presented value doesn't match.

  * `{:error, :disabled}` — the feature is turned off in
    config.
  """
  @spec consume(binary()) ::
          {:ok, map()}
          | {:error, :not_pending | :invalid_code | :disabled}
  def consume(presented) when is_binary(presented) do
    cond do
      not enabled?() ->
        {:error, :disabled}

      not File.regular?(path()) ->
        {:error, :not_pending}

      true ->
        do_consume(presented)
    end
  end

  defp do_consume(presented) do
    case File.read(path()) do
      {:ok, contents} ->
        stored = String.trim(contents)

        if Crypto.secure_compare(stored, presented) do
          # Order matters: issue the token first so a
          # crash between deleting the file and issuing
          # the token doesn't leave the operator locked
          # out.
          {:ok, token} =
            TokenStore.issue(%{
              role: :cluster_admin,
              scopes: ["*"],
              label: "bootstrap (first-run)"
            })

          File.rm(path())
          {:ok, token}
        else
          {:error, :invalid_code}
        end

      {:error, _} ->
        {:error, :not_pending}
    end
  end

  @doc """
  Generate a fresh bootstrap code, write it to the
  configured path with mode 0600, return it. Used by
  `mix exdns.bootstrap.generate` (Tier 1 mix task) and
  by tests; the production install path is the shell
  installer.
  """
  @spec generate!() :: binary()
  def generate! do
    code = :crypto.strong_rand_bytes(24) |> Base.url_encode64(padding: false)

    File.mkdir_p!(Path.dirname(path()))
    File.write!(path(), code <> "\n")
    File.chmod!(path(), 0o600)

    code
  end

  @doc "Path to the bootstrap-code file (per config)."
  @spec path() :: Path.t()
  def path do
    config() |> Keyword.get(:code_path, @default_path)
  end

  defp enabled? do
    config() |> Keyword.get(:enabled, true)
  end

  defp config do
    Application.get_env(:ex_dns, :bootstrap, [])
  end
end
