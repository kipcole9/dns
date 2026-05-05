defmodule ExDns.DNSSEC.NSEC3 do
  @moduledoc """
  RFC 5155 NSEC3 hash + chain primitives used by the signer to
  produce NSEC3 records for an authoritative zone.

  ## Hash function

  RFC 5155 §5 defines exactly one hash algorithm (number `1`) —
  iterated SHA-1 with an optional salt:

      H(x)    = SHA-1(canonical(x) || salt)
      H^k(x)  = H(H^(k-1)(x))

  `iterations` controls the iteration count (RFC 9276 recommends
  `0` to mitigate enumeration attacks; we default to `0`).

  ## Owner-name encoding

  The hashed owner is **base32hex** (RFC 4648, lower-case, no
  padding). The full NSEC3 owner name is
  `<base32hex(hash)>.<zone>`.

  ## Public API

  * `hash_name/3` — compute the hash for a single name.

  * `hashed_owner/3` — compute the full owner name
    (`base32hex.zone`).

  Higher-level chain construction lives in
  `ExDns.DNSSEC.NSEC3.Chain` (next module).
  """

  alias ExDns.Message

  @hash_algorithm_sha1 1

  @doc """
  Returns the only hash algorithm number defined by RFC 5155
  (`1` = SHA-1).

  ### Examples

      iex> ExDns.DNSSEC.NSEC3.hash_algorithm()
      1

  """
  @spec hash_algorithm() :: 1
  def hash_algorithm, do: @hash_algorithm_sha1

  @doc """
  Compute the iterated, salted SHA-1 hash of `name` per RFC 5155 §5.

  ### Arguments

  * `name` is the FQDN being hashed (binary).

  * `salt` is the per-zone salt (binary; may be `<<>>`).

  * `iterations` is the iteration count.

  ### Returns

  * The 20-byte raw hash (binary).

  ### Examples

      iex> hash = ExDns.DNSSEC.NSEC3.hash_name("example.com", <<>>, 0)
      iex> byte_size(hash)
      20

  """
  @spec hash_name(binary(), binary(), non_neg_integer()) :: binary()
  def hash_name(name, salt, iterations)
      when is_binary(name) and is_binary(salt) and is_integer(iterations) and iterations >= 0 do
    initial = :crypto.hash(:sha, Message.encode_name(canonical(name)) <> salt)
    iterate(initial, salt, iterations)
  end

  defp iterate(hash, _salt, 0), do: hash

  defp iterate(hash, salt, n) when n > 0 do
    iterate(:crypto.hash(:sha, hash <> salt), salt, n - 1)
  end

  @doc """
  Compute the NSEC3 owner name for `name` in `zone`:
  `<base32hex(hash(name))>.<zone>`.

  ### Arguments

  * `name` is the FQDN whose NSEC3 owner is being computed.
  * `zone` is the zone apex.
  * `options` is a keyword list:

  ### Options

  * `:salt` — defaults to `<<>>`.
  * `:iterations` — defaults to `0` (per RFC 9276).

  ### Returns

  * The owner name as a lower-case binary.

  ### Examples

      iex> name = ExDns.DNSSEC.NSEC3.hashed_owner("host.example.com", "example.com")
      iex> String.ends_with?(name, ".example.com")
      true

  """
  @spec hashed_owner(binary(), binary(), keyword()) :: binary()
  def hashed_owner(name, zone, options \\ []) when is_binary(name) and is_binary(zone) do
    salt = Keyword.get(options, :salt, <<>>)
    iterations = Keyword.get(options, :iterations, 0)

    hash = hash_name(name, salt, iterations)
    encoded = Base.hex_encode32(hash, case: :lower, padding: false)

    encoded <> "." <> canonical(zone)
  end

  @doc """
  Build the NSEC3 owner name from a pre-computed hash (skip the
  hashing step). Useful inside the chain constructor where the
  same hashes are computed once and reused.

  ### Arguments

  * `hash` is the 20-byte raw hash.
  * `zone` is the zone apex.

  ### Returns

  * The owner name as a lower-case binary.

  ### Examples

      iex> hash = ExDns.DNSSEC.NSEC3.hash_name("x.test", <<>>, 0)
      iex> ExDns.DNSSEC.NSEC3.hashed_owner_from_hash(hash, "test")
      ...> |> String.ends_with?(".test")
      true

  """
  @spec hashed_owner_from_hash(binary(), binary()) :: binary()
  def hashed_owner_from_hash(hash, zone) when is_binary(hash) and is_binary(zone) do
    Base.hex_encode32(hash, case: :lower, padding: false) <> "." <> canonical(zone)
  end

  defp canonical(name) when is_binary(name) do
    name |> String.downcase(:ascii) |> String.trim_trailing(".")
  end
end
