defmodule ExDns.Zone.Journal.Storage do
  @moduledoc """
  Storage backend behaviour for the IXFR journal.

  Implementations:

  * `ExDns.Zone.Journal.Storage.ETS` — in-memory only. Lost on
    restart; secondaries fall back to AXFR after a node bounce.
    Default.

  * `ExDns.Zone.Journal.Storage.DETS` — disk-backed via Erlang's
    DETS. Survives restarts; opens a single file per instance.

  Configure via:

      config :ex_dns, :journal,
        backend: ExDns.Zone.Journal.Storage.DETS,
        path: "/var/lib/exdns/journal.dets"
  """

  alias ExDns.Zone.Journal.Entry

  @type apex :: binary()
  @type serial :: non_neg_integer()

  @doc """
  Initialise the backend. Idempotent. Returns the implementation's
  handle (typically the table name atom).
  """
  @callback init(keyword()) :: term()

  @doc "Drop every entry."
  @callback clear() :: :ok

  @doc "Insert a journal entry. The {apex, serial} pair is the unique key."
  @callback insert(apex(), serial(), Entry.t()) :: :ok

  @doc "Return every entry recorded for `apex`, in any order."
  @callback entries(apex()) :: [Entry.t()]

  @doc """
  Return the configured backend module, defaulting to the in-
  memory ETS implementation.
  """
  @spec backend() :: module()
  def backend do
    Application.get_env(:ex_dns, :journal, [])
    |> Keyword.get(:backend, ExDns.Zone.Journal.Storage.ETS)
  end

  @doc """
  Return the keyword list of options the configured backend was
  built with.
  """
  @spec backend_options() :: keyword()
  def backend_options do
    Application.get_env(:ex_dns, :journal, [])
  end
end
