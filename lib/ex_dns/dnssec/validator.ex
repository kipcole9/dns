defmodule ExDns.DNSSEC.Validator do
  @moduledoc """
  Cryptographic verification primitives for DNSSEC (RFC 4034 / 4035 /
  6840 / 8624).

  Three operations:

  * `verify_rrset/3` — given an RRset, an `RRSIG` covering it, and the
    `DNSKEY` whose Key Tag the RRSIG references, verify the signature.
  * `verify_ds/3` — given a `DS` record, the owner name it sits at,
    and a candidate `DNSKEY`, verify that the DS is the correct
    digest of the DNSKEY (used at delegation points to bridge
    parent → child trust).
  * `key_tag/1` — compute the 16-bit Key Tag of a DNSKEY using the
    algorithm in RFC 4034 Appendix B.

  ## Algorithm support

  * **8** — RSA/SHA-256 (RSASHA256). The most widely deployed
    algorithm; required for any serious validator.
  * **13** — ECDSA P-256 with SHA-256 (ECDSAP256SHA256). The modern
    default for new zones.
  * **15** — Ed25519. Modern preferred; supported via `:crypto`.

  Older algorithms (RSA/SHA-1, RSA/SHA-512, etc.) and newer
  experimental ones are not implemented in this first cut.

  ## Canonical form caveats

  RFC 4034 §6 defines a strict canonical form for RRsets being
  signed/verified. We honour:

  * Lower-case owner names.
  * Records sorted by canonical RDATA bytes.
  * TTL replaced by the RRSIG's `original_ttl`.
  * Uncompressed name encoding throughout (we never use name
    compression on encode for record RDATA, which fits the canonical
    requirement naturally).

  Embedded domain names inside RDATA (e.g., MX target, SOA mname/rname,
  NS server) MUST also be lowercased for canonical form. Our RR
  modules store names without case folding, so we lowercase
  defensively when encoding for signing.

  """

  alias ExDns.Message
  alias ExDns.Resource.{DNSKEY, DS, RRSIG}

  @doc """
  Verifies an RRset against an RRSIG using a candidate DNSKEY.

  ### Returns

  * `:ok` — the signature is valid.
  * `{:error, :wrong_key}` — the DNSKEY's algorithm + key tag don't
    match the RRSIG's.
  * `{:error, :unsupported_algorithm}` — algorithm not implemented.
  * `{:error, :bad_signature}` — the signature does not verify.

  """
  @spec verify_rrset([struct()], RRSIG.t(), DNSKEY.t()) ::
          :ok | {:error, atom()}
  def verify_rrset(records, %RRSIG{} = rrsig, %DNSKEY{} = dnskey)
      when is_list(records) and records != [] do
    cond do
      not ExDns.DNSSEC.AlgorithmPolicy.validation_allowed?(rrsig.algorithm) ->
        {:error, :algorithm_disallowed}

      rrsig.algorithm != dnskey.algorithm ->
        {:error, :wrong_key}

      rrsig.key_tag != key_tag(dnskey) ->
        {:error, :wrong_key}

      true ->
        do_verify_rrset(records, rrsig, dnskey)
    end
  end

  defp do_verify_rrset(records, rrsig, dnskey) do
    signed_data = canonical_signing_data(records, rrsig)
    verify_signature(rrsig.algorithm, signed_data, rrsig.signature, dnskey.public_key)
  end

  @doc """
  Verifies that a DS record matches a candidate DNSKEY.

  Per RFC 4034 §5.1, the DS digest is

      digest = HASH(owner_name_canonical || DNSKEY_RDATA_canonical)

  ### Returns

  * `:ok` — the DS matches the DNSKEY.
  * `{:error, :wrong_key_tag}` / `{:error, :wrong_algorithm}` —
    the DS references a different key.
  * `{:error, :unsupported_digest_type}`.
  * `{:error, :bad_digest}` — the computed digest doesn't match.

  """
  @spec verify_ds(DS.t(), binary(), DNSKEY.t()) :: :ok | {:error, atom()}
  def verify_ds(%DS{} = ds, owner, %DNSKEY{} = dnskey) when is_binary(owner) do
    cond do
      ds.algorithm != dnskey.algorithm -> {:error, :wrong_algorithm}
      ds.key_tag != key_tag(dnskey) -> {:error, :wrong_key_tag}
      true -> compare_digest(ds, owner, dnskey)
    end
  end

  defp compare_digest(ds, owner, dnskey) do
    case digest_function(ds.digest_type) do
      :error ->
        {:error, :unsupported_digest_type}

      hash ->
        owner_bytes = Message.encode_name(String.downcase(owner, :ascii))
        dnskey_rdata = encode_dnskey_rdata(dnskey)
        computed = :crypto.hash(hash, owner_bytes <> dnskey_rdata)

        if computed == ds.digest do
          :ok
        else
          {:error, :bad_digest}
        end
    end
  end

  defp digest_function(1), do: :sha
  defp digest_function(2), do: :sha256
  defp digest_function(4), do: :sha384
  defp digest_function(_), do: :error

  @doc """
  Computes the Key Tag of a DNSKEY (RFC 4034 Appendix B).

  For algorithms other than 1 (RSA/MD5, deprecated), the algorithm
  is the one-pass folded checksum on the RDATA bytes.
  """
  @spec key_tag(DNSKEY.t()) :: non_neg_integer()
  def key_tag(%DNSKEY{} = dnskey) do
    rdata = encode_dnskey_rdata(dnskey)

    {sum, _} =
      Enum.reduce(:binary.bin_to_list(rdata), {0, 0}, fn byte, {acc, i} ->
        if rem(i, 2) == 0 do
          {acc + byte * 256, i + 1}
        else
          {acc + byte, i + 1}
        end
      end)

    rem(sum + Bitwise.bsr(sum, 16), 0x10000)
  end

  defp encode_dnskey_rdata(%DNSKEY{
         flags: flags,
         protocol: protocol,
         algorithm: algorithm,
         public_key: public_key
       }) do
    <<flags::size(16), protocol::size(8), algorithm::size(8), public_key::binary>>
  end

  # ----- canonical signing data --------------------------------------

  defp canonical_signing_data(records, rrsig) do
    canonical_records = Enum.map(records, &canonical_record(&1, rrsig.original_ttl))
    sorted = Enum.sort_by(canonical_records, & &1.rdata)
    encoded_records = Enum.map(sorted, &encode_canonical_record/1)

    rrsig_data = canonical_rrsig_signing_fields(rrsig)
    IO.iodata_to_binary([rrsig_data | encoded_records])
  end

  defp canonical_record(record, original_ttl) do
    type = type_for_struct(record)
    type_int = ExDns.Resource.type_from(type)
    class_int = ExDns.Resource.class_for(record.class)
    rdata = canonical_rdata(record)

    %{
      owner: String.downcase(record.name, :ascii),
      type: type_int,
      class: class_int,
      ttl: original_ttl,
      rdata: rdata
    }
  end

  defp encode_canonical_record(canonical) do
    name_bytes = Message.encode_name(canonical.owner)
    rdata = canonical.rdata

    <<
      name_bytes::binary,
      canonical.type::size(16),
      canonical.class::size(16),
      canonical.ttl::size(32),
      byte_size(rdata)::size(16),
      rdata::binary
    >>
  end

  defp canonical_rdata(record) do
    type = type_for_struct(record)
    module = ExDns.Resource.module_for(type)

    if module do
      module.encode(record)
      |> IO.iodata_to_binary()
      |> lowercase_embedded_names(record)
    else
      raise ArgumentError, "Cannot canonicalise unknown record type: #{inspect(record)}"
    end
  end

  # For RR types whose RDATA contains domain names we re-encode the
  # whole record after lowercasing the embedded name fields. The set
  # of types is small and well-defined.
  defp lowercase_embedded_names(rdata, %ExDns.Resource.NS{} = record) do
    record
    |> Map.update!(:server, &String.downcase(&1, :ascii))
    |> ExDns.Resource.NS.encode()
    |> IO.iodata_to_binary()
    |> case do
      bytes -> bytes
    end

    _ = rdata
    record
    |> Map.update!(:server, &String.downcase(&1, :ascii))
    |> ExDns.Resource.NS.encode()
    |> IO.iodata_to_binary()
  end

  defp lowercase_embedded_names(_rdata, %ExDns.Resource.CNAME{} = record) do
    record
    |> Map.update!(:server, &String.downcase(&1, :ascii))
    |> ExDns.Resource.CNAME.encode()
    |> IO.iodata_to_binary()
  end

  defp lowercase_embedded_names(_rdata, %ExDns.Resource.PTR{} = record) do
    record
    |> Map.update!(:pointer, &String.downcase(&1, :ascii))
    |> ExDns.Resource.PTR.encode()
    |> IO.iodata_to_binary()
  end

  defp lowercase_embedded_names(_rdata, %ExDns.Resource.MX{} = record) do
    record
    |> Map.update!(:server, &String.downcase(&1, :ascii))
    |> ExDns.Resource.MX.encode()
    |> IO.iodata_to_binary()
  end

  defp lowercase_embedded_names(_rdata, %ExDns.Resource.SOA{} = record) do
    record
    |> Map.update!(:mname, &String.downcase(&1, :ascii))
    |> Map.update!(:email, &String.downcase(&1, :ascii))
    |> ExDns.Resource.SOA.encode()
    |> IO.iodata_to_binary()
  end

  defp lowercase_embedded_names(_rdata, %ExDns.Resource.DNAME{} = record) do
    record
    |> Map.update!(:target, &String.downcase(&1, :ascii))
    |> ExDns.Resource.DNAME.encode()
    |> IO.iodata_to_binary()
  end

  defp lowercase_embedded_names(_rdata, %ExDns.Resource.SRV{} = record) do
    record
    |> Map.update!(:target, &String.downcase(&1, :ascii))
    |> ExDns.Resource.SRV.encode()
    |> IO.iodata_to_binary()
  end

  defp lowercase_embedded_names(rdata, _record), do: rdata

  defp canonical_rrsig_signing_fields(%RRSIG{} = rrsig) do
    type_covered_int = ExDns.Resource.type_from(rrsig.type_covered)

    <<
      type_covered_int::size(16),
      rrsig.algorithm::size(8),
      rrsig.labels::size(8),
      rrsig.original_ttl::size(32),
      rrsig.signature_expiration::size(32),
      rrsig.signature_inception::size(32),
      rrsig.key_tag::size(16),
      Message.encode_name(String.downcase(rrsig.signer, :ascii))::binary
    >>
  end

  defp type_for_struct(%module{}) do
    module
    |> Module.split()
    |> List.last()
    |> String.downcase()
    |> String.to_existing_atom()
  end

  # ----- signature verification --------------------------------------

  # Algorithm 8: RSA/SHA-256
  defp verify_signature(8, signed_data, signature, public_key) do
    case parse_rsa_public_key(public_key) do
      {:ok, [exponent, modulus]} ->
        if :crypto.verify(:rsa, :sha256, signed_data, signature, [exponent, modulus]) do
          :ok
        else
          {:error, :bad_signature}
        end

      {:error, _} = error ->
        error
    end
  end

  # Algorithm 13: ECDSA P-256 / SHA-256
  defp verify_signature(13, signed_data, signature, public_key)
       when byte_size(public_key) == 64 and byte_size(signature) == 64 do
    der = ecdsa_signature_to_der(signature)
    point = <<0x04, public_key::binary>>

    if :crypto.verify(:ecdsa, :sha256, signed_data, der, [point, :secp256r1]) do
      :ok
    else
      {:error, :bad_signature}
    end
  end

  # Algorithm 15: Ed25519
  defp verify_signature(15, signed_data, signature, public_key)
       when byte_size(public_key) == 32 and byte_size(signature) == 64 do
    if :crypto.verify(:eddsa, :none, signed_data, signature, [public_key, :ed25519]) do
      :ok
    else
      {:error, :bad_signature}
    end
  end

  defp verify_signature(_alg, _data, _sig, _key), do: {:error, :unsupported_algorithm}

  # RFC 3110: DNSKEY public key for RSA is `[exp_len, exp, modulus]`
  # with `exp_len` either a single byte (when the exponent fits in
  # 0–255 bytes), or `<<0, exp_len::16>>` for larger exponents.
  defp parse_rsa_public_key(<<0::size(8), exp_len::size(16), rest::binary>>) do
    parse_rsa_split(exp_len, rest)
  end

  defp parse_rsa_public_key(<<exp_len::size(8), rest::binary>>) do
    parse_rsa_split(exp_len, rest)
  end

  defp parse_rsa_public_key(_), do: {:error, :malformed_rsa_key}

  defp parse_rsa_split(exp_len, rest) do
    case rest do
      <<exp::binary-size(^exp_len), modulus::binary>> ->
        {:ok, [:binary.decode_unsigned(exp), :binary.decode_unsigned(modulus)]}

      _ ->
        {:error, :malformed_rsa_key}
    end
  end

  # ECDSA-P256 signatures on the DNSSEC wire are 64 raw bytes (r || s).
  # `:crypto.verify(:ecdsa, ...)` expects DER-encoded ASN.1; convert.
  defp ecdsa_signature_to_der(<<r::binary-size(32), s::binary-size(32)>>) do
    encode_der_integer_pair(r, s)
  end

  defp encode_der_integer_pair(r, s) do
    r_int = encode_der_integer(r)
    s_int = encode_der_integer(s)
    body = r_int <> s_int
    <<0x30, byte_size(body)::size(8), body::binary>>
  end

  defp encode_der_integer(bytes) do
    case trim_leading_zeros(bytes) do
      # MSB of the trimmed value is set — DER would read it as a
      # negative integer. Prepend a single 0x00 to keep the value
      # positive. This matters because raw-form ECDSA r/s are
      # unsigned 256-bit integers; ~1/256 of them happen to have
      # their leading byte zero, and of those ~1/2 have the next
      # byte ≥ 0x80. Without the re-pad here, OpenSSL rejects the
      # DER and verification flakes intermittently.
      <<top, _::binary>> = trimmed when top >= 0x80 ->
        <<0x02, byte_size(trimmed) + 1::size(8), 0x00, trimmed::binary>>

      trimmed ->
        <<0x02, byte_size(trimmed)::size(8), trimmed::binary>>
    end
  end

  defp trim_leading_zeros(<<0, rest::binary>>) when byte_size(rest) > 0, do: trim_leading_zeros(rest)
  defp trim_leading_zeros(other), do: other
end
