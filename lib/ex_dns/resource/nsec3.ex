defmodule ExDns.Resource.NSEC3 do
  @moduledoc """
  Manages the NSEC3 DNSSEC resource record (RFC 5155).

  Type code 50.

  ### NSEC3 RDATA format

      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Hash Alg | Flags |
      | Iterations (16 bits)        |
      | Salt Length (8 bits)        |
      | Salt (variable)             |
      | Hash Length (8 bits)        |
      | Next Hashed Owner (variable)|
      | Type Bit Maps (variable)    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  """

  @behaviour ExDns.Resource
  @behaviour ExDns.Resource.JSON

  defstruct [
    :name,
    :ttl,
    :class,
    :hash_algorithm,
    :flags,
    :iterations,
    :salt,
    :next_hashed_owner,
    :type_bit_maps
  ]

  import ExDns.Resource.Validation

  @doc """
  Builds an NSEC3 record from a parser-produced keyword
  list. Field renames: `:next_hash` → `:next_hashed_owner`,
  `:types` → `:type_bit_maps`.
  """
  def new(resource) when is_list(resource) do
    resource
    |> rename(:next_hash, :next_hashed_owner)
    |> rename(:types, :type_bit_maps)
    |> validate_integer(:ttl)
    |> validate_integer(:hash_algorithm)
    |> validate_integer(:flags)
    |> validate_integer(:iterations)
    |> validate_class(:class, :internet)
    |> structify_if_valid(__MODULE__)
  end

  defp rename(resource, from, to) do
    case Keyword.pop(resource, from) do
      {nil, _} -> resource
      {value, rest} -> Keyword.put(rest, to, value)
    end
  end

  @impl ExDns.Resource
  def decode(rdata, _message) do
    <<hash_algorithm::size(8), flags::size(8), iterations::size(16), salt_len::size(8),
      salt::binary-size(salt_len), hash_len::size(8),
      next_hashed_owner::binary-size(hash_len), type_bit_maps::binary>> = rdata

    %__MODULE__{
      hash_algorithm: hash_algorithm,
      flags: flags,
      iterations: iterations,
      salt: salt,
      next_hashed_owner: next_hashed_owner,
      type_bit_maps: type_bit_maps
    }
  end

  @impl ExDns.Resource
  def encode(%__MODULE__{
        hash_algorithm: hash_algorithm,
        flags: flags,
        iterations: iterations,
        salt: salt,
        next_hashed_owner: next_hashed_owner,
        type_bit_maps: type_bit_maps
      }) do
    <<hash_algorithm::size(8), flags::size(8), iterations::size(16), byte_size(salt)::size(8),
      salt::binary, byte_size(next_hashed_owner)::size(8), next_hashed_owner::binary,
      type_bit_maps::binary>>
  end

  @impl ExDns.Resource
  def format(%__MODULE__{} = resource) do
    [
      ExDns.Resource.format_preamble(resource, "NSEC3"),
      Integer.to_string(resource.hash_algorithm),
      " ",
      Integer.to_string(resource.flags),
      " ",
      Integer.to_string(resource.iterations),
      " ",
      if(resource.salt == <<>>, do: "-", else: Base.encode16(resource.salt, case: :lower)),
      " ",
      Base.encode32(resource.next_hashed_owner, case: :lower, padding: false),
      " ",
      Base.encode16(resource.type_bit_maps, case: :lower)
    ]
  end

  defimpl ExDns.Resource.Format do
    def format(resource), do: ExDns.Resource.NSEC3.format(resource)
  end

  @impl ExDns.Resource.JSON
  def encode_rdata(%__MODULE__{} = nsec3) do
    %{
      "hash_algorithm" => nsec3.hash_algorithm,
      "flags" => nsec3.flags,
      "iterations" => nsec3.iterations,
      "salt" => Base.encode16(nsec3.salt || <<>>, case: :lower),
      "next_hashed_owner" =>
        Base.hex_encode32(nsec3.next_hashed_owner || <<>>, padding: false, case: :lower),
      "types" => stringify_types(nsec3.type_bit_maps)
    }
  end

  defp stringify_types(types) when is_list(types) do
    Enum.map(types, fn
      atom when is_atom(atom) -> atom |> Atom.to_string() |> String.upcase()
      other -> to_string(other)
    end)
  end

  defp stringify_types(_), do: []
end
