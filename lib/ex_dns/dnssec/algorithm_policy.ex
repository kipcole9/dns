defmodule ExDns.DNSSEC.AlgorithmPolicy do
  @moduledoc """
  RFC 8624 cryptographic-algorithm policy for DNSSEC.

  Codifies the IETF's deployment guidance: which algorithms
  may be used for signing, which for validation, and which are
  forbidden in either direction. Loaded once and consulted by
  the signer (`ExDns.DNSSEC.Signer`), validator
  (`ExDns.DNSSEC.Validator`), and key generator
  (`ExDns.DNSSEC.Rollover`).

  ## Status table (RFC 8624 §3.1)

  | Number | Algorithm                    | Sign            | Validate         |
  |--------|------------------------------|-----------------|------------------|
  |   1    | RSA/MD5                      | MUST NOT        | MUST NOT         |
  |   3    | DSA/SHA-1                    | MUST NOT        | MUST NOT         |
  |   5    | RSA/SHA-1                    | NOT RECOMMENDED | MUST             |
  |   6    | DSA-NSEC3-SHA1               | MUST NOT        | MUST NOT         |
  |   7    | RSASHA1-NSEC3-SHA1           | NOT RECOMMENDED | MUST             |
  |   8    | RSA/SHA-256                  | MUST            | MUST             |
  |  10    | RSA/SHA-512                  | NOT RECOMMENDED | MUST             |
  |  12    | GOST R 34.10-2001            | MUST NOT        | MAY              |
  |  13    | ECDSA P-256/SHA-256          | MUST            | MUST             |
  |  14    | ECDSA P-384/SHA-384          | MAY             | RECOMMENDED      |
  |  15    | Ed25519                      | RECOMMENDED     | RECOMMENDED      |
  |  16    | Ed448                        | MAY             | RECOMMENDED      |

  ## Policy application

  * `signing_allowed?/1` returns `false` for any algorithm
    classified MUST-NOT for signing. NOT-RECOMMENDED algorithms
    return `true` by default but `false` when the operator sets
    `:strict, true` (recommended for new deployments).

  * `validation_allowed?/1` returns `false` only for MUST-NOT
    algorithms. Validators MUST accept NOT-RECOMMENDED
    algorithms for backwards compatibility with deployed
    zones.

  ## Configuration

      config :ex_dns, :dnssec_algorithm_policy,
        # When true, refuse to sign with NOT-RECOMMENDED algorithms
        # (RSA/SHA-1, RSASHA1-NSEC3-SHA1, RSA/SHA-512). Default
        # false for backwards compatibility.
        strict: false
  """

  @must_not_sign [1, 3, 6, 12]
  @must_not_validate [1, 3, 6]
  @not_recommended_for_signing [5, 7, 10]

  @doc """
  Is signing with `algorithm` permitted under the current policy?

  ### Arguments

  * `algorithm` is the IANA DNSSEC algorithm number.

  ### Returns

  * `true` when permitted.
  * `false` when forbidden by RFC 8624 (MUST-NOT for signing) or
    when `:strict` is enabled and the algorithm is NOT-RECOMMENDED.

  ### Examples

      iex> ExDns.DNSSEC.AlgorithmPolicy.signing_allowed?(13)
      true

      iex> ExDns.DNSSEC.AlgorithmPolicy.signing_allowed?(1)
      false

  """
  @spec signing_allowed?(non_neg_integer()) :: boolean()
  def signing_allowed?(algorithm) when is_integer(algorithm) do
    cond do
      algorithm in @must_not_sign ->
        false

      strict?() and algorithm in @not_recommended_for_signing ->
        false

      true ->
        true
    end
  end

  @doc """
  Is validation of a signature produced by `algorithm` permitted?

  Per RFC 8624, validators MUST accept NOT-RECOMMENDED
  algorithms — refusing would break working zones. Only the
  small set of truly-broken algorithms is rejected.

  ### Arguments

  * `algorithm` is the IANA DNSSEC algorithm number.

  ### Returns

  * `true` when validation may proceed.
  * `false` when the algorithm is MUST-NOT for validation.

  ### Examples

      iex> ExDns.DNSSEC.AlgorithmPolicy.validation_allowed?(13)
      true

      iex> ExDns.DNSSEC.AlgorithmPolicy.validation_allowed?(3)
      false

  """
  @spec validation_allowed?(non_neg_integer()) :: boolean()
  def validation_allowed?(algorithm) when is_integer(algorithm) do
    algorithm not in @must_not_validate
  end

  @doc """
  Classify `algorithm` for human-readable surfaces (logs,
  admin UI).

  ### Returns

  * `:must` | `:recommended` | `:may` | `:not_recommended` |
    `:must_not` for the signing direction.
  """
  @spec sign_status(non_neg_integer()) :: atom()
  def sign_status(algorithm) do
    case algorithm do
      8 -> :must
      13 -> :must
      15 -> :recommended
      14 -> :may
      16 -> :may
      n when n in @not_recommended_for_signing -> :not_recommended
      n when n in @must_not_sign -> :must_not
      _ -> :unknown
    end
  end

  @doc """
  Same as `sign_status/1` but for the validator side.
  """
  @spec validate_status(non_neg_integer()) :: atom()
  def validate_status(algorithm) do
    case algorithm do
      8 -> :must
      13 -> :must
      5 -> :must
      7 -> :must
      10 -> :must
      14 -> :recommended
      15 -> :recommended
      16 -> :recommended
      12 -> :may
      n when n in @must_not_validate -> :must_not
      _ -> :unknown
    end
  end

  defp strict? do
    Application.get_env(:ex_dns, :dnssec_algorithm_policy, [])
    |> Keyword.get(:strict, false)
  end
end
