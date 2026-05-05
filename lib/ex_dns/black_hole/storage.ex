defmodule ExDns.BlackHole.Storage do
  @moduledoc """
  Behaviour for BlackHole's persistent state.

  ## Why a behaviour

  BlackHole's state — blocklists, allowlist, denylist, groups,
  query log — has two viable storage stories:

  * `ExDns.BlackHole.Storage.EKV` (default) — replicates
    cluster-wide via the shared EKV instance. Same code path
    works single-node and clustered.

  * `ExDns.BlackHole.Storage.SQLite` — single-file SQLite via
    `exqlite`. Better fit for very high-rate query log
    ingestion or single-node deployments that want a
    portable on-disk file.

  ## Public API

  Operators don't talk to the backend directly. They use the
  module-level wrappers below, which dispatch to the
  configured adapter.

  ## Configuration

  Use the EKV backend (default — no config needed):

      # implicit
      # config :ex_dns, :black_hole, []

  Or pin SQLite explicitly:

      config :ex_dns, :black_hole,
        storage:
          {ExDns.BlackHole.Storage.SQLite,
           [path: "/var/lib/exdns/black_hole.sqlite"]}
  """

  @type backend_state :: term()

  @callback init(options :: keyword()) :: {:ok, backend_state()} | {:error, term()}

  @callback list_blocklists(backend_state()) :: [map()]
  @callback put_blocklist(backend_state(), map()) :: {:ok, map()} | {:error, term()}
  @callback delete_blocklist(backend_state(), id :: binary()) :: :ok

  @callback list_allow(backend_state()) :: [map()]
  @callback put_allow(backend_state(), map()) :: {:ok, map()} | {:error, term()}
  @callback delete_allow(backend_state(), domain :: binary()) :: :ok

  @callback list_deny(backend_state()) :: [map()]
  @callback put_deny(backend_state(), map()) :: {:ok, map()} | {:error, term()}
  @callback delete_deny(backend_state(), domain :: binary()) :: :ok

  @callback list_groups(backend_state()) :: [map()]
  @callback put_group(backend_state(), map()) :: {:ok, map()} | {:error, term()}
  @callback delete_group(backend_state(), id :: binary()) :: :ok

  @callback append_query_log(backend_state(), entry :: map()) :: :ok
  @callback read_query_log(backend_state(), query :: map()) ::
              %{rows: [map()], next_cursor: term() | nil}
  @callback truncate_query_log(backend_state()) :: :ok
  @callback delete_query_log_before(backend_state(), ts_ns :: integer()) :: :ok

  @callback put_kv(backend_state(), key :: binary(), value :: term()) :: :ok
  @callback get_kv(backend_state(), key :: binary()) :: {:ok, term()} | :error

  # ----- module-level wrappers --------------------------------------

  @doc """
  Initialise the configured backend. Caches the
  `{module, state}` tuple in `:persistent_term` so subsequent
  calls are lock-free.
  """
  @spec init() :: :ok | {:error, term()}
  def init do
    {module, options} = configured_backend()

    case module.init(options) do
      {:ok, state} ->
        :persistent_term.put(__MODULE__, {module, state})
        :ok

      {:error, _} = err ->
        err
    end
  end

  @doc "Returns the cached `{module, state}` tuple, raising if `init/0` was never called."
  @spec backend() :: {module(), backend_state()}
  def backend do
    :persistent_term.get(__MODULE__)
  end

  defp configured_backend do
    case Application.get_env(:ex_dns, :black_hole, []) do
      list when is_list(list) ->
        case Keyword.get(list, :storage) do
          {module, options} when is_atom(module) and is_list(options) -> {module, options}
          _ -> default_backend()
        end

      _ ->
        default_backend()
    end
  end

  defp default_backend do
    {ExDns.BlackHole.Storage.EKV, []}
  end

  # ----- delegations ------------------------------------------------

  for fun <- [
        :list_blocklists,
        :list_allow,
        :list_deny,
        :list_groups
      ] do
    @doc false
    def unquote(fun)() do
      {module, state} = backend()
      apply(module, unquote(fun), [state])
    end
  end

  for fun <- [
        :put_blocklist,
        :put_allow,
        :put_deny,
        :put_group
      ] do
    @doc false
    def unquote(fun)(map) do
      {module, state} = backend()
      apply(module, unquote(fun), [state, map])
    end
  end

  for fun <- [
        :delete_blocklist,
        :delete_allow,
        :delete_deny,
        :delete_group
      ] do
    @doc false
    def unquote(fun)(id) do
      {module, state} = backend()
      apply(module, unquote(fun), [state, id])
    end
  end

  @doc false
  def append_query_log(entry) do
    {module, state} = backend()
    module.append_query_log(state, entry)
  end

  @doc false
  def read_query_log(query) do
    {module, state} = backend()
    module.read_query_log(state, query)
  end

  @doc false
  def truncate_query_log do
    {module, state} = backend()
    module.truncate_query_log(state)
  end

  @doc false
  def delete_query_log_before(ts_ns) do
    {module, state} = backend()
    module.delete_query_log_before(state, ts_ns)
  end

  @doc false
  def put_kv(key, value) do
    {module, state} = backend()
    module.put_kv(state, key, value)
  end

  @doc false
  def get_kv(key) do
    {module, state} = backend()
    module.get_kv(state, key)
  end
end
