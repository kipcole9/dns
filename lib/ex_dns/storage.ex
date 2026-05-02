defmodule ExDns.Storage do
  @moduledoc """
  Behaviour describing a zone-storage backend.

  One backend ships today:

  * `ExDns.Storage.ETS` — single-node, in-memory. Default.

  A clustered backend (Khepri) is the planned next step — see
  `plans/2026-05-02-storage-alternatives.md` for the rationale.

  Configure the active backend with:

      config :ex_dns, storage: ExDns.Storage.ETS

  All ExDns code reaches the backend via this module's wrapper
  functions, never directly. That keeps the storage choice swappable
  without touching the resolver, listeners, or zone loader.

  """

  @type apex :: binary()
  @type qname :: binary()
  @type qtype :: atom()
  @type rr :: struct()

  @callback init() :: :ok
  @callback put_zone(apex, [rr]) :: :ok
  @callback delete_zone(apex) :: :ok
  @callback zones() :: [apex]
  @callback find_zone(qname) :: apex | nil
  @callback lookup(qname, qtype) :: {:ok, apex, [rr]} | {:error, :nxdomain}
  @callback lookup(apex, qname, qtype) :: {:ok, apex, [rr]} | {:error, :nxdomain}
  @callback lookup_any(qname) :: {:ok, apex, [rr]} | {:error, :nxdomain}
  @callback lookup_any(apex, qname) :: {:ok, apex, [rr]} | {:error, :nxdomain}
  @callback lookup_wildcard(qname, qtype) :: {:ok, apex, [rr]} | {:error, :nxdomain}
  @callback wildcard_name_exists?(qname) :: {:ok, apex} | false
  @callback find_delegation(qname) ::
              {:ok, apex, qname, [rr]} | :no_delegation
  @callback dump_zone(apex) :: {:ok, [rr]} | {:error, :not_loaded}

  @default_backend ExDns.Storage.ETS

  @doc "Returns the configured storage backend module."
  @spec backend() :: module()
  def backend do
    Application.get_env(:ex_dns, :storage, @default_backend)
  end

  # --- Public wrappers -------------------------------------------------

  def init, do: backend().init()
  def put_zone(apex, records), do: backend().put_zone(apex, records)
  def delete_zone(apex), do: backend().delete_zone(apex)
  def zones, do: backend().zones()
  def find_zone(qname), do: backend().find_zone(qname)
  def lookup(qname, qtype), do: backend().lookup(qname, qtype)
  def lookup(apex, qname, qtype), do: backend().lookup(apex, qname, qtype)
  def lookup_any(qname), do: backend().lookup_any(qname)
  def lookup_any(apex, qname), do: backend().lookup_any(apex, qname)
  def lookup_wildcard(qname, qtype), do: backend().lookup_wildcard(qname, qtype)
  def wildcard_name_exists?(qname), do: backend().wildcard_name_exists?(qname)
  def find_delegation(qname), do: backend().find_delegation(qname)
  def dump_zone(apex), do: backend().dump_zone(apex)
end
