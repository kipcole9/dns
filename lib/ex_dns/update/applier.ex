defmodule ExDns.Update.Applier do
  @moduledoc """
  Apply the **Update Section** of an RFC 2136 message to a
  loaded zone. Atomic — either every operation lands or none
  does. Bumps the zone's SOA serial automatically (RFC 2136
  §3.6) so secondaries notice the change.

  ## Operation classification (RFC 2136 §2.5)

  | CLASS | TTL | RDLEN | TYPE   | Operation                                        |
  |-------|-----|-------|--------|--------------------------------------------------|
  | zone  | ttl |  >0   | rrtype | Add the given RR (or replace at name+type)       |
  | ANY   |  0  |   0   | ANY    | Delete every RRset at the name                   |
  | ANY   |  0  |   0   | rrtype | Delete the named RRset of TYPE                   |
  | NONE  |  0  |  >0   | rrtype | Delete the specific RR (matching all of name+type+rdata) |

  ## Atomicity

  Loads the current zone, builds the post-update record list
  in memory, validates the result still has an SOA at the
  apex, then calls `Storage.put_zone/2` once. The single put
  triggers the existing journal + outbound NOTIFY pipelines
  exactly as a normal zone reload would.

  ## SOA serial bump

  RFC 2136 §3.6 requires the SOA serial to advance whenever
  any update is applied. The applier increments by 1, wrapping
  via RFC 1982 arithmetic.
  """

  alias ExDns.Resource.SOA
  alias ExDns.Storage

  @typedoc "An UPDATE-section record from the message Authority section."
  @type update_record :: struct()

  @doc """
  Apply `updates` to `apex`.

  ### Arguments

  * `apex` — zone apex from the UPDATE's Zone section.
  * `updates` — list of resource records from the message's
    Authority section, classified per RFC 2136 §2.5.
  * `class` — the zone's class atom (typically `:in`).

  ### Returns

  * `:ok` when every operation applied and the zone was
    re-stored.

  * `{:error, rcode}` when:
    * `8` — REFUSED-equivalent for an unknown class/operation
      shape (mapped to NOTIMP-style refusal).
    * `9` — NOTAUTH (we're not authoritative for this apex).
    * `5` — REFUSED (the result would have no SOA).
  """
  @spec apply([update_record()], binary(), atom()) :: :ok | {:error, 0..23}
  def apply(updates, apex, class) when is_list(updates) do
    apex_norm = normalise(apex)

    case Storage.dump_zone(apex_norm) do
      {:ok, current_records} ->
        case build_new_records(current_records, updates, class) do
          {:ok, new_records} ->
            new_records_with_serial = bump_serial(new_records, apex_norm)

            cond do
              not has_soa?(new_records_with_serial, apex_norm) ->
                {:error, 5}

              true ->
                Storage.put_zone(apex_norm, new_records_with_serial)
                ExDns.Zone.Snapshot.Writer.request()
                :ok
            end

          {:error, _} = err ->
            err
        end

      {:error, :not_loaded} ->
        {:error, 9}
    end
  end

  # ----- record-list builder ---------------------------------------

  defp build_new_records(current, updates, class) do
    Enum.reduce_while(updates, {:ok, current}, fn update, {:ok, records} ->
      case apply_one(records, update, class) do
        {:ok, new} -> {:cont, {:ok, new}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  # Add: zone class, TTL >= 0, rdata present.
  defp apply_one(records, %{class: zone_class, ttl: ttl} = rr, zone_class)
       when is_integer(ttl) do
    name = normalise(rr.name)
    type = type_of(rr)
    # RFC 2136 §3.4.2.2: a duplicate add is silently absorbed.
    same? = Enum.any?(records, fn r -> normalise(r.name) == name and type_of(r) == type and erase_ttl(r) == erase_ttl(rr) end)

    if same?, do: {:ok, records}, else: {:ok, records ++ [rr]}
  end

  # Delete every RRset at name (CLASS=ANY, type would be ANY in
  # the wire form; we don't reliably get a typed struct for that
  # so this clause matches when the explicit class is :any).
  defp apply_one(records, %{class: :any, ttl: 0} = rr, _zone_class) do
    name = normalise(rr.name)

    case type_of(rr) do
      :unknown ->
        # Form: delete every RRset at name.
        {:ok, Enum.reject(records, fn r -> normalise(r.name) == name end)}

      type ->
        # Form: delete the named RRset of TYPE.
        {:ok, Enum.reject(records, fn r -> normalise(r.name) == name and type_of(r) == type end)}
    end
  end

  # Delete a specific RR (CLASS=NONE, RDATA present).
  defp apply_one(records, %{class: :none, ttl: 0} = rr, _zone_class) do
    name = normalise(rr.name)
    type = type_of(rr)
    # RFC 2136 §2.5.4: the equality test is over name + type +
    # RDATA. CLASS=NONE is the operation discriminator, not part
    # of the comparison — strip class + ttl from both sides.
    target = normalise_for_compare(rr)

    {:ok,
     Enum.reject(records, fn r ->
       normalise(r.name) == name and type_of(r) == type and
         normalise_for_compare(r) == target
     end)}
  end

  defp apply_one(_records, _other, _zone_class), do: {:error, 1}

  defp normalise_for_compare(record) do
    record |> Map.put(:ttl, 0) |> Map.put(:class, :in)
  end

  # ----- SOA bookkeeping -------------------------------------------

  defp has_soa?(records, apex) do
    Enum.any?(records, fn r ->
      match?(%SOA{}, r) and normalise(r.name) == apex
    end)
  end

  defp bump_serial(records, apex) do
    Enum.map(records, fn
      %SOA{name: name} = soa ->
        if normalise(name) == apex do
          %SOA{soa | serial: rem(soa.serial + 1, 0x100000000)}
        else
          soa
        end

      other ->
        other
    end)
  end

  # ----- helpers ---------------------------------------------------

  defp type_of(%module{}) do
    atom_name = module |> Module.split() |> List.last() |> String.downcase()

    try do
      String.to_existing_atom(atom_name)
    rescue
      ArgumentError -> :unknown
    end
  end

  defp type_of(_), do: :unknown

  defp erase_ttl(record), do: %{record | ttl: 0}

  defp normalise(name) when is_binary(name) do
    name |> String.trim_trailing(".") |> String.downcase(:ascii)
  end
end
