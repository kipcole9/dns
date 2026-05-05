defmodule ExDns.Zone.Snapshot do
  @moduledoc """
  On-disk snapshot of every loaded zone, so runtime mutations
  survive a restart.

  ## Why

  Zones are loaded from files on start. Runtime sources of
  mutation — RFC 2136 dynamic UPDATE, catalog-zone applies,
  secondary AXFR/IXFR — write into the in-memory store but
  *not* back to the source files. Without a snapshot, every
  restart loses those changes and the zone reverts to whatever
  the source files contain.

  This module persists a single binary snapshot containing the
  full record set of every zone in `ExDns.Storage`, plus a
  metadata header. On startup, after the file-based loader runs,
  the snapshot is replayed so runtime changes overlay the
  file baseline.

  ## File format

  ```
    <<"EXDNSZSNAP\\0", version::8, payload::binary>>
  ```

  where `payload` is `:erlang.term_to_binary/1` of:

  ```
    %{
      written_at_unix: integer(),
      zones: %{apex :: binary() => [record :: struct()]}
    }
  ```

  Version is `1`. A future schema change bumps this byte and
  `read/1` returns `{:error, {:bad_version, v}}` on mismatch
  rather than risk replaying garbage.

  ## Configuration

      config :ex_dns, :zone_snapshot,
        enabled: true,
        path: "/var/lib/exdns/snapshot.bin"

  Default path: `Path.join(System.tmp_dir!(), "ex_dns_zone_snapshot.bin")`.
  Operators running on systemd should override to a persistent
  StateDirectory.
  """

  alias ExDns.Storage

  require Logger

  @magic "EXDNSZSNAP\0"
  @version 1

  @doc """
  Writes a snapshot of every zone currently in `ExDns.Storage`
  to `path`.

  ### Arguments

  * `path` is the destination file path. Parent directories are
    created if missing.

  ### Returns

  * `{:ok, %{zones: count, bytes: byte_size}}` on success.
  * `{:error, reason}` when the dump or file write fails.

  ### Examples

      iex> path = Path.join(System.tmp_dir!(),
      ...>   "snap-doctest-\#{System.unique_integer([:positive])}.bin")
      iex> ExDns.Storage.init()
      iex> {:ok, %{zones: _, bytes: _}} = ExDns.Zone.Snapshot.write(path)
      iex> File.rm(path)
      :ok

  """
  @spec write(Path.t()) :: {:ok, %{zones: non_neg_integer(), bytes: non_neg_integer()}} | {:error, term()}
  def write(path) when is_binary(path) do
    with :ok <- File.mkdir_p(Path.dirname(path)),
         {:ok, payload} <- collect_payload() do
      bin = encode(payload)

      case File.write(path, bin) do
        :ok ->
          {:ok, %{zones: map_size(payload.zones), bytes: byte_size(bin)}}

        {:error, _} = err ->
          err
      end
    end
  end

  @doc """
  Read a snapshot file and return its decoded payload.

  ### Arguments

  * `path` is the snapshot file's path.

  ### Returns

  * `{:ok, %{written_at_unix: integer, zones: map}}` on success.
  * `{:error, :enoent}` when the file does not exist.
  * `{:error, :bad_magic}` when the file is not a snapshot.
  * `{:error, {:bad_version, integer}}` when the schema version
    does not match this build.
  * `{:error, :corrupt}` when the payload fails to decode.

  ### Examples

      iex> ExDns.Zone.Snapshot.read("/no/such/snapshot.bin")
      {:error, :enoent}

  """
  @spec read(Path.t()) ::
          {:ok, %{written_at_unix: integer(), zones: %{binary() => [struct()]}}}
          | {:error, term()}
  def read(path) when is_binary(path) do
    with {:ok, bin} <- File.read(path) do
      decode(bin)
    end
  end

  @doc """
  Replay a snapshot into `ExDns.Storage`. Each zone in the
  snapshot is installed via `ExDns.Storage.put_zone/2` —
  overwriting any zone of the same apex already present.

  ### Arguments

  * `path` is the snapshot file's path.

  ### Returns

  * `{:ok, count}` — number of zones replayed.
  * `{:error, reason}` — passed through from `read/1`. A
    missing file (`:enoent`) is the common case at first
    boot and is still reported as `{:error, :enoent}` so the
    caller can treat it as a no-op.
  """
  @spec replay(Path.t()) :: {:ok, non_neg_integer()} | {:error, term()}
  def replay(path) when is_binary(path) do
    with {:ok, %{zones: zones}} <- read(path) do
      Enum.each(zones, fn {apex, records} -> Storage.put_zone(apex, records) end)
      {:ok, map_size(zones)}
    end
  end

  @doc """
  The configured snapshot path, suitable for `write/1` and
  `replay/1`.
  """
  @spec configured_path() :: Path.t()
  def configured_path do
    Application.get_env(:ex_dns, :zone_snapshot, [])
    |> Keyword.get(:path, default_path())
  end

  @doc "Whether the auto-snapshot writer is enabled in config."
  @spec enabled?() :: boolean()
  def enabled? do
    Application.get_env(:ex_dns, :zone_snapshot, [])
    |> Keyword.get(:enabled, false)
  end

  defp default_path do
    Path.join(System.tmp_dir!(), "ex_dns_zone_snapshot.bin")
  end

  # ----- internals --------------------------------------------------

  defp collect_payload do
    zones =
      Storage.zones()
      |> Enum.reduce(%{}, fn apex, acc ->
        case Storage.dump_zone(apex) do
          {:ok, records} -> Map.put(acc, apex, records)
          {:error, _} -> acc
        end
      end)

    {:ok, %{written_at_unix: System.os_time(:second), zones: zones}}
  end

  defp encode(payload) do
    @magic <> <<@version::8>> <> :erlang.term_to_binary(payload)
  end

  defp decode(<<@magic, @version::8, body::binary>>) do
    try do
      {:ok, :erlang.binary_to_term(body, [:safe])}
    rescue
      _ -> {:error, :corrupt}
    end
  end

  defp decode(<<@magic, version::8, _::binary>>) do
    {:error, {:bad_version, version}}
  end

  defp decode(_), do: {:error, :bad_magic}
end
