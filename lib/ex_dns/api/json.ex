defmodule ExDns.API.JSON do
  @moduledoc """
  JSON layer for the `/api/v1` surface.

  The per-type rdata shapes live with each `ExDns.Resource.*`
  module (see `ExDns.Resource.JSON`). This module is the thin
  dispatcher that:

  1. Wraps a record into the canonical
     `%{id, name, type, ttl, class, rdata}` envelope.
  2. Delegates rdata encoding to the resource module.
  3. Computes a deterministic short id over the record so
     PATCH/DELETE clients can target a specific record across
     requests.

  ## Encode helper

  `encode!/1` wraps `:json.encode/1` so callers always get a
  binary back rather than iodata.
  """

  @doc "Encode `term` to a JSON binary."
  @spec encode!(term()) :: binary()
  def encode!(term) do
    term |> :json.encode() |> IO.iodata_to_binary()
  end

  @doc """
  Render an `%ExDns.Resource.*{}` struct to its API JSON
  envelope: `%{id, name, type, ttl, class, rdata}`.

  When the struct's module does not implement
  `ExDns.Resource.JSON`, `rdata` is `%{}`.
  """
  @spec record(struct()) :: map()
  def record(%struct{} = r) do
    %{
      "id" => record_id(r),
      "name" => trim_dot(Map.get(r, :name)),
      "type" => qtype_for(struct),
      "ttl" => Map.get(r, :ttl),
      "class" => class_string(Map.get(r, :class)),
      "rdata" => encode_rdata(r)
    }
  end

  @doc """
  Deterministic short id for a record. Stable across requests
  for the same `{name, type, rdata}`. Used by record-mutation
  endpoints (PATCH/DELETE) so clients can target an individual
  record.
  """
  @spec record_id(struct()) :: binary()
  def record_id(%_{} = r) do
    payload =
      %{
        name: trim_dot(Map.get(r, :name)),
        type: qtype_for(r.__struct__),
        rdata: encode_rdata(r)
      }
      |> :erlang.term_to_binary()

    :crypto.hash(:sha256, payload)
    |> binary_part(0, 8)
    |> Base.url_encode64(padding: false)
  end

  defp encode_rdata(%struct{} = r) do
    if function_exported?(struct, :encode_rdata, 1) do
      struct.encode_rdata(r)
    else
      %{}
    end
  end

  # ----- helpers --------------------------------------------------

  defp qtype_for(struct_module) do
    struct_module |> Module.split() |> List.last() |> String.upcase()
  end

  defp class_string(:in), do: "IN"
  defp class_string(:internet), do: "IN"
  defp class_string(:ch), do: "CH"
  defp class_string(:hs), do: "HS"
  defp class_string(other), do: to_string(other)

  defp trim_dot(nil), do: nil
  defp trim_dot(name) when is_binary(name), do: String.trim_trailing(name, ".")
  defp trim_dot(other), do: other
end
