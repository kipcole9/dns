defmodule ExDns.ExtendedDNSErrors do
  @moduledoc """
  Extended DNS Errors (EDE, RFC 8914) — EDNS(0) option code
  `15`.

  EDE attaches structured "why" information to a response so a
  validating resolver, monitoring pipeline, or browser dev-tool
  can tell *why* a query failed instead of guessing from the
  rcode alone. Without EDE the only signal a SERVFAIL carries
  is "something went wrong"; with EDE the response says "DNSSEC
  signature expired", "blocked by RPZ policy", "no reachable
  authority", and so on.

  ## Wire format (RFC 8914 §2)

      +0  INFO-CODE (16 bits big-endian)
      +2  EXTRA-TEXT (variable, UTF-8; may be empty)

  Multiple EDE options may appear in a single response — they
  compose, not override. The receiver SHOULD render all of
  them.

  ## INFO-CODE registry

  This module exposes the IANA-registered codes as named atoms
  so callers don't have to remember the integer values. Unknown
  codes round-trip as integers.

  | Code | Atom                                  |
  |------|---------------------------------------|
  |   0  | `:other`                              |
  |   1  | `:unsupported_dnskey_algorithm`       |
  |   2  | `:unsupported_ds_digest`              |
  |   3  | `:stale_answer`                       |
  |   4  | `:forged_answer`                      |
  |   5  | `:dnssec_indeterminate`               |
  |   6  | `:dnssec_bogus`                       |
  |   7  | `:signature_expired`                  |
  |   8  | `:signature_not_yet_valid`            |
  |   9  | `:dnskey_missing`                     |
  |  10  | `:rrsigs_missing`                     |
  |  11  | `:no_zone_key_bit_set`                |
  |  12  | `:nsec_missing`                       |
  |  13  | `:cached_error`                       |
  |  14  | `:not_ready`                          |
  |  15  | `:blocked`                            |
  |  16  | `:censored`                           |
  |  17  | `:filtered`                           |
  |  18  | `:prohibited`                         |
  |  19  | `:stale_nxdomain_answer`              |
  |  20  | `:not_authoritative`                  |
  |  21  | `:not_supported`                      |
  |  22  | `:no_reachable_authority`             |
  |  23  | `:network_error`                      |
  |  24  | `:invalid_data`                       |
  |  25  | `:signature_expired_before_valid`     |
  |  26  | `:too_early`                          |
  |  27  | `:unsupported_nsec3_iterations_value` |
  |  28  | `:unable_to_conform_to_policy`        |
  |  29  | `:synthesized`                        |
  """

  @option_code 15

  @info_code_atoms %{
    0 => :other,
    1 => :unsupported_dnskey_algorithm,
    2 => :unsupported_ds_digest,
    3 => :stale_answer,
    4 => :forged_answer,
    5 => :dnssec_indeterminate,
    6 => :dnssec_bogus,
    7 => :signature_expired,
    8 => :signature_not_yet_valid,
    9 => :dnskey_missing,
    10 => :rrsigs_missing,
    11 => :no_zone_key_bit_set,
    12 => :nsec_missing,
    13 => :cached_error,
    14 => :not_ready,
    15 => :blocked,
    16 => :censored,
    17 => :filtered,
    18 => :prohibited,
    19 => :stale_nxdomain_answer,
    20 => :not_authoritative,
    21 => :not_supported,
    22 => :no_reachable_authority,
    23 => :network_error,
    24 => :invalid_data,
    25 => :signature_expired_before_valid,
    26 => :too_early,
    27 => :unsupported_nsec3_iterations_value,
    28 => :unable_to_conform_to_policy,
    29 => :synthesized
  }

  @atom_to_info_code Map.new(@info_code_atoms, fn {k, v} -> {v, k} end)

  @doc """
  Returns the IANA option code for EDE (`15`).

  ### Examples

      iex> ExDns.ExtendedDNSErrors.option_code()
      15

  """
  @spec option_code() :: 15
  def option_code, do: @option_code

  @doc """
  Encode an EDE option payload.

  ### Arguments

  * `info_code` — either an integer (`0..0xFFFF`) or one of the
    named atoms in the table above.

  * `extra_text` — UTF-8 string with operator-friendly extra
    detail (defaults to `""`).

  ### Returns

  * `{15, payload_binary}` ready to drop into an OPT record's
    `:options` list.

  ### Examples

      iex> ExDns.ExtendedDNSErrors.encode_option(:dnssec_bogus, "RRSIG over A doesn't verify")
      {15, <<0, 6, "RRSIG over A doesn't verify">>}

  """
  @spec encode_option(non_neg_integer() | atom(), binary()) ::
          {non_neg_integer(), binary()}
  def encode_option(info_code, extra_text \\ "")
      when is_binary(extra_text) do
    code_int = to_info_code(info_code)
    {@option_code, <<code_int::size(16), extra_text::binary>>}
  end

  @doc """
  Decode the option's payload back into a `{info_code, extra_text}`
  tuple. The `info_code` is returned as a named atom when one is
  registered, otherwise as a raw integer.

  ### Examples

      iex> ExDns.ExtendedDNSErrors.decode_payload(<<0, 6, "boom">>)
      {:dnssec_bogus, "boom"}

  """
  @spec decode_payload(binary()) :: {atom() | non_neg_integer(), binary()}
  def decode_payload(<<info_code::size(16), extra_text::binary>>) do
    {Map.get(@info_code_atoms, info_code, info_code), extra_text}
  end

  def decode_payload(_), do: {:other, ""}

  @doc """
  Find every EDE option in an OPT options list and decode them.
  Multiple EDEs may appear in a single response (RFC 8914 §3).

  ### Arguments

  * `options` — `[{code, binary}]` from an OPT record.

  ### Returns

  * `[{info_code, extra_text}]` — empty when no EDE present.

  ### Examples

      iex> ExDns.ExtendedDNSErrors.find_in_options([])
      []

  """
  @spec find_in_options([{non_neg_integer(), binary()}]) ::
          [{atom() | non_neg_integer(), binary()}]
  def find_in_options(options) when is_list(options) do
    for {@option_code, payload} <- options, do: decode_payload(payload)
  end

  # ----- internals --------------------------------------------------

  defp to_info_code(int) when is_integer(int) and int in 0..0xFFFF, do: int

  defp to_info_code(atom) when is_atom(atom) do
    case Map.fetch(@atom_to_info_code, atom) do
      {:ok, code} -> code
      :error -> raise ArgumentError, "unknown EDE atom #{inspect(atom)}"
    end
  end
end
