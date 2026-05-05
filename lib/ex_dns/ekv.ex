defmodule ExDns.EKV do
  @moduledoc """
  Single-instance wrapper around the [EKV](https://hex.pm/packages/ekv)
  embedded KV store. EKV is the cluster substrate the rest of
  ExDns's persistence layers swap onto by default.

  ## Why one instance per BEAM

  Every subsystem that wants persistent state shares this
  one EKV instance and namespaces its keys by prefix:

  * `plugin/registry`               — plugin registry map
  * `plugin/route_index`            — flat route table
  * `tsig/keys`                     — TSIG keyring map
  * `dnssec/<zone>/keys`            — DNSSEC key list per zone
  * `blackhole/blocklist/<id>`      — one blocklist row
  * `blackhole/allow/<domain>`      — one allowlist entry
  * `blackhole/deny/<domain>`       — one denylist entry
  * `blackhole/group/<id>`          — one group row
  * `blackhole/kv/<key>`            — generic kv slot
  * `zone/<apex>/rrset/<name>/<type>` — per-RRset record list

  Operators editing state by hand can `EKV.scan` the prefix
  to inspect any subsystem's data without per-subsystem
  tooling.

  ## Single-node vs cluster

  EKV's API is identical between modes. A single-node
  deployment runs with `cluster_size: 1` (the default here);
  the day a second node joins, the operator raises
  `cluster_size` and the same code keeps working — no schema
  migration, no separate adapter code path.

  ## Configuration

      config :ex_dns, :ekv,
        enabled: true,
        data_dir: "/var/lib/exdns/ekv",
        cluster_size: 1,
        mode: :member

  Defaults: enabled, `data_dir` under `System.tmp_dir!()` (so
  tests Just Work), `cluster_size: 1`, `mode: :member`.

  ## Public surface

  * `child_spec/1` — for the supervision tree.
  * `name/0` — the registered EKV instance name (`:ex_dns`).
  * `lookup/1`, `get/1`, `put/2`, `put/3`, `delete/1`,
    `update/2`, `update/3`, `scan/1`, `keys/1`, `subscribe/1`,
    `unsubscribe/1` — thin wrappers that elide the instance
    name + give us a stable surface to mock in tests.
  """

  @name :ex_dns

  @doc "The registered EKV instance name."
  def name, do: @name

  @doc """
  Child spec for the supervision tree. Reads
  `:ex_dns, :ekv, [...]` for `:data_dir`, `:cluster_size`,
  `:mode`, plus optional `:region` / `:region_routing` for
  multi-region clusters.
  """
  def child_spec(_options \\ []) do
    options = Application.get_env(:ex_dns, :ekv, [])

    spec_options =
      [
        name: @name,
        data_dir: Keyword.get(options, :data_dir, default_data_dir()),
        cluster_size: Keyword.get(options, :cluster_size, 1),
        mode: Keyword.get(options, :mode, :member),
        # Block startup until this EKV member can serve reads
        # — without this gate, callers in the same boot
        # window can race the per-shard replica
        # initialisation and crash with "no persistent term
        # stored" from `EKV.read_conn/2`.
        wait_for_quorum:
          Keyword.get(options, :wait_for_quorum, :timer.seconds(10))
      ]
      |> maybe_add(:region, options[:region])
      |> maybe_add(:region_routing, options[:region_routing])

    EKV.child_spec(spec_options)
  end

  @doc "Whether EKV is enabled in config (default: true)."
  @spec enabled?() :: boolean()
  def enabled? do
    Application.get_env(:ex_dns, :ekv, [])
    |> Keyword.get(:enabled, true)
  end

  defp default_data_dir do
    Path.join([System.tmp_dir!(), "ex_dns_ekv"])
  end

  defp maybe_add(opts, _key, nil), do: opts
  defp maybe_add(opts, key, value), do: Keyword.put(opts, key, value)

  # Tests sometimes stop the `:ex_dns` application (and so
  # tear down EKV) without restarting it; subsequent code
  # then crashes deep inside EKV with a missing process or
  # persistent_term entry. Auto-restart the application so
  # callers see a live EKV regardless. The replica process
  # name is the canonical liveness signal — its
  # `persistent_term` config can outlive the supervisor
  # whereas the named process cannot.
  defp ensure_started! do
    if Process.whereis(:ex_dns_ekv_replica_0) == nil do
      {:ok, _} = Application.ensure_all_started(:ex_dns)
    end

    :ok
  end

  # ----- thin wrappers ----------------------------------------------

  @doc """
  Eventually-consistent local read. Returns the stored term
  (any Elixir term) or `nil` when the key is missing.
  """
  def lookup(key) when is_binary(key) do
    ensure_started!()

    case EKV.lookup(@name, key) do
      nil -> nil
      {value, _meta} -> value
      value -> value
    end
  end

  @doc """
  Same as `lookup/1` but linearizable (round-trip to quorum).
  Returns the stored term or `nil`.
  """
  def get(key) when is_binary(key) do
    ensure_started!()

    case EKV.get(@name, key, consistent: true) do
      nil -> nil
      {:ok, value} -> value
      {:ok, value, _vsn} -> value
      {value, _meta} -> value
      value -> value
    end
  end

  @doc """
  Put `value` under `key`.

  Non-CAS writes return `:ok`. CAS writes (when `:if_vsn`
  or `:consistent: true` is in `opts`) return
  `{:ok, version}` / `{:error, :conflict}`.
  """
  def put(key, value, opts \\ []) when is_binary(key) do
    ensure_started!()
    EKV.put(@name, key, value, opts)
  end

  @doc "Delete `key`. Returns `:ok` (or `{:error, …}` on CAS conflict)."
  def delete(key, opts \\ []) when is_binary(key) do
    ensure_started!()
    EKV.delete(@name, key, opts)
  end

  @doc """
  CAS read-modify-write. `fun` receives the current value
  (or `nil`) and returns the new value. Retries on conflict
  per `:max_retries` option (default 5).
  """
  def update(key, fun, opts \\ []) when is_binary(key) and is_function(fun, 1) do
    ensure_started!()
    EKV.update(@name, key, fun, opts)
  end

  @doc "Scan keys matching `prefix`. Returns a Stream of {key, value, meta}."
  def scan(prefix) when is_binary(prefix) do
    ensure_started!()
    EKV.scan(@name, prefix)
  end

  @doc "Return only keys matching `prefix` (with their version)."
  def keys(prefix) when is_binary(prefix) do
    ensure_started!()
    EKV.keys(@name, prefix)
  end

  @doc "Subscribe the calling process to changes under `prefix`."
  def subscribe(prefix) when is_binary(prefix) do
    ensure_started!()
    EKV.subscribe(@name, prefix)
  end

  @doc "Unsubscribe."
  def unsubscribe(prefix) when is_binary(prefix) do
    ensure_started!()
    EKV.unsubscribe(@name, prefix)
  end
end
