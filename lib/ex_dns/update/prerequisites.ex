defmodule ExDns.Update.Prerequisites do
  @moduledoc """
  Evaluate the **prerequisite section** of an RFC 2136 UPDATE
  message — the records the client demands to be true (or
  false) about the zone before any of its update operations
  apply.

  ## Wire encoding

  Each prerequisite is a regular RR whose CLASS, TTL, and
  RDLENGTH fields are repurposed per RFC 2136 §2.4. There are
  five forms:

  | Form | CLASS | TTL | RDLEN | TYPE     | Meaning                                          |
  |------|-------|-----|-------|----------|--------------------------------------------------|
  | (1)  | ANY   |  0  |  0    | ANY      | Name MUST exist (any RRset)                      |
  | (2)  | ANY   |  0  |  0    | rrtype   | RRset of TYPE must exist                         |
  | (3)  | NONE  |  0  |  0    | ANY      | Name MUST NOT exist                              |
  | (4)  | NONE  |  0  |  0    | rrtype   | RRset of TYPE must NOT exist                     |
  | (5)  | zone  |  0  | >0    | rrtype   | RRset must exist with **exactly** these records  |

  ## Result

  `check/3` returns `:ok` when every prerequisite is satisfied,
  or `{:error, rcode}` with the RFC 2136-mandated rcode for
  the first failure:

  * `8` — NXRRSET (RRset that should exist, doesn't)
  * `7` — YXRRSET (RRset that shouldn't exist, does)
  * `3` — NXDOMAIN (name that should exist, doesn't)
  * `6` — YXDOMAIN (name that shouldn't exist, does)
  * `0` — NOERROR (everything's fine)
  """

  alias ExDns.Storage

  @type prereq :: struct()
  @type rcode :: 0..23

  @doc """
  Check every prerequisite against current zone state.

  ### Arguments

  * `apex` — the zone apex from the UPDATE's Zone section.
  * `prereqs` — list of resource-record structs from the
    Prerequisite section.
  * `class` — the zone's class atom (typically `:in`).

  ### Returns

  * `:ok` when every prerequisite is satisfied.
  * `{:error, rcode}` on the first failure (RFC 2136 §3.2
    mandates the specific rcodes listed above).
  """
  @spec check(binary(), [prereq()], atom()) :: :ok | {:error, rcode()}
  def check(apex, prereqs, class) when is_list(prereqs) do
    Enum.reduce_while(prereqs, :ok, fn prereq, _acc ->
      case classify(prereq, class) do
        {:must_exist_rrset, name, type} -> rrset_exists(apex, name, type)
        {:must_not_exist_rrset, name, type} -> rrset_absent(apex, name, type)
        {:must_exist_exact_rrset, name, type, records} -> rrset_exact(apex, name, type, records)
        # Type-ANY prereqs (forms 1 + 3) and unrecognised shapes
        # turn into FORMERR — kept narrow for the MVP. The
        # forms most-used in the wild (2, 4, 5) are above.
        :unknown -> {:halt, {:error, 1}}
      end
      |> wrap()
    end)
  end

  defp wrap(:ok), do: {:cont, :ok}
  defp wrap({:error, _} = err), do: {:halt, err}

  # ----- classification --------------------------------------------

  # Form (2): RRset of TYPE must exist (CLASS=ANY, TTL=0, no rdata).
  defp classify(%{class: :any, ttl: 0, name: name} = rr, _zone_class) do
    case type_of(rr) do
      :unknown -> :unknown
      type -> {:must_exist_rrset, name, type}
    end
  end

  # Form (4): RRset of TYPE must not exist (CLASS=NONE, TTL=0, no rdata).
  defp classify(%{class: :none, ttl: 0, name: name} = rr, _zone_class) do
    case type_of(rr) do
      :unknown -> :unknown
      type -> {:must_not_exist_rrset, name, type}
    end
  end

  # Form (5): zone class + TTL=0 + RDATA present.
  defp classify(%{class: zone_class, ttl: 0, name: name} = rr, zone_class) do
    case type_of(rr) do
      :unknown -> :unknown
      type -> {:must_exist_exact_rrset, name, type, [rr]}
    end
  end

  defp classify(_, _), do: :unknown

  # ----- predicates -------------------------------------------------

  defp rrset_exists(apex, name, type) do
    case Storage.lookup(apex, name, type) do
      {:ok, _apex, [_ | _]} -> :ok
      _ -> {:error, 8}
    end
  end

  defp rrset_absent(apex, name, type) do
    case Storage.lookup(apex, name, type) do
      {:ok, _apex, [_ | _]} -> {:error, 7}
      _ -> :ok
    end
  end

  defp rrset_exact(apex, name, type, expected) do
    case Storage.lookup(apex, name, type) do
      {:ok, _apex, current} when length(current) == length(expected) ->
        if rrset_match?(current, expected), do: :ok, else: {:error, 8}

      _ ->
        {:error, 8}
    end
  end

  # Compare two RRsets ignoring TTL and order.
  defp rrset_match?(a, b) do
    Enum.sort(strip_ttl(a)) == Enum.sort(strip_ttl(b))
  end

  defp strip_ttl(records) do
    Enum.map(records, fn r -> %{r | ttl: 0} end)
  end

  # Map a record struct to its qtype atom, e.g.
  # `%ExDns.Resource.A{}` → `:a`. Returns `:unknown` for anything
  # whose module name doesn't decode to a known qtype.
  defp type_of(%module{}) do
    atom_name = module |> Module.split() |> List.last() |> String.downcase()

    try do
      String.to_existing_atom(atom_name)
    rescue
      ArgumentError -> :unknown
    end
  end

  defp type_of(_), do: :unknown
end
